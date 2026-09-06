"""Everything the service does, as plain methods that return a Result. http.py only translates HTTP to these calls."""
from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import quote

from . import passkeys
from .gate import decide
from .words import new_code, normalize

RATE_WINDOW = 300
RATE_LIMIT = 10
OPTIONS_LIMIT = 240     # login-options calls per window from one caller: far above any real person, far below a flood
CHALLENGE_TTL = 300     # seconds a WebAuthn challenge stays valid
ENROLL_TTL = 900        # seconds a member or the owner has to finish making a passkey after redeeming a code


@dataclass
class Result:
    status: int
    body: dict | None = None
    cookie: str | None = None       # a complete Set-Cookie value
    redirect: str | None = None     # a Location; body is ignored when set
    headers: dict = field(default_factory=dict)


def parse_ttl(text: str | None, default_days: int = 7, max_days: int = 365) -> int:
    if not text:
        return default_days * 86400
    m = re.fullmatch(r"(\d{1,4})([hd])", text.strip().lower())
    if not m:
        raise ValueError("ttl looks like 3d or 12h")
    seconds = int(m.group(1)) * (3600 if m.group(2) == "h" else 86400)
    if seconds <= 0 or seconds > max_days * 86400:
        raise ValueError("ttl must be between 1h and 365d")
    return seconds


class AuthService:
    def __init__(self, cfg, store, now=time.time):
        self.cfg, self.store, self.now = cfg, store, now

    # ---------- cookies ----------
    def cookie(self, token: str, max_age: int) -> str:
        c = self.cfg
        return f"{c.cookie_name}={token}; Domain={c.cookie_domain}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax"

    def clear_cookie(self) -> str:
        return self.cookie("", 0)

    # ---------- helpers ----------
    def _session(self, token):
        s = self.store.session_by_token(token) if token else None
        if not s or s.revoked_at is not None or s.expires_at <= self.now():
            return None, None
        u = self.store.user_by_id(s.user_id)
        if not u or u.disabled:
            return None, None
        return s, u

    def _owner(self, token):
        s, u = self._session(token)
        if not s or u.role != "owner" or s.invite_id is not None:
            return None
        return u

    def _sites_out(self, user) -> dict:
        if user.role == "owner":
            return {"hosts": ["*"], "sites": ["*"]}
        names = {host: name for name, host in self.cfg.aliases.items()}
        return {"hosts": list(user.sites), "sites": [names.get(h, h) for h in user.sites]}

    def _invite_link(self, code: str, user) -> str:
        """The link an invite is sent as, and where redeeming it lands.

        Someone whose whole world is one site should arrive on that site, not on a terminal they
        then have to work out — so an invite that leaves its holder with exactly one site carries
        that site's root as the destination. Two or more and there is no single right answer, so the
        link stays bare and lands on the terminal, which is where a person with a choice should
        start. The owner's `*` is not a host and is filtered out here: without that this would ask
        the browser for `https://*/`.

        The two halves ride in different parts of the URL on purpose, and they are not
        interchangeable. The code stays in the fragment so it never reaches a server log. The
        destination goes in the query because the login page reads `next` from `location.search`,
        and because the moment it has the code it scrubs the address bar by rewriting the URL as
        path + search — a destination in the fragment would be thrown away with the code it was
        travelling next to."""
        link = f"{self.cfg.origin}{self.cfg.login_path}"
        hosts = [h for h in user.sites if h in self.cfg.hosts]
        if len(hosts) == 1:
            link += f"?next={quote(f'https://{hosts[0]}/', safe='')}"
        return f"{link}#i={code}"

    def _hosts_from_names(self, names) -> list:
        hosts = []
        for n in names or []:
            h = self.cfg.host_for(str(n))
            if h == self.cfg.apex:
                raise ValueError("everyone signed in can already reach the apex; it doesn't need granting")
            if not h:
                raise ValueError(f"no such site: {n}")
            hosts.append(h)
        return hosts

    def _blocked(self, key: str, limit: int = RATE_LIMIT) -> bool:
        return self.store.failures(key, self.now(), RATE_WINDOW) >= limit

    def _fail(self, key: str, status: int = 401, error: str = "permission denied") -> Result:
        self.store.note_failure(key, self.now(), RATE_WINDOW)
        return Result(status, {"error": error})

    def _start_session(self, user, invite_id, expires_at: float, user_agent: str) -> Result:
        token = secrets.token_urlsafe(32)
        self.store.create_session(token, user.id, invite_id, expires_at, user_agent or "", self.now())
        return Result(200, {"name": user.name, "role": user.role, **self._sites_out(user)}, cookie=self.cookie(token, int(expires_at - self.now())))

    # ---------- the gate ----------
    def verify(self, token, host: str, method: str, uri: str, accept: str) -> Result:
        s, u = self._session(token)
        d = decide(u, s, host or "", self.now(), self.cfg.apex)
        page_load = (method or "GET").upper() == "GET" and "text/html" in (accept or "")
        if d.status == 200:
            self.store.touch_session(s.id, self.now())
            return Result(200, {"ok": True}, headers={"X-Doorman-User": d.user, "X-Doorman-Role": d.role})
        if d.status == 401:
            # A request names its own Host header, so only redirect back to it when it is one of ours;
            # anything else (an unknown or attacker-supplied host) falls back to the origin, same as no host at all.
            target = f"https://{host}{uri or '/'}" if host in self.cfg.hosts else self.cfg.origin + "/"
            if page_load:
                return Result(302, redirect=f"{self.cfg.origin}{self.cfg.login_path}?next={quote(target, safe='')}")
            return Result(401, {"error": "login required"})
        if page_load:
            return Result(302, redirect=f"{self.cfg.origin}{self.cfg.denied_path}?host={quote(host or '', safe='')}")
        return Result(403, {"error": "not on your list"})

    def me(self, token) -> Result:
        s, u = self._session(token)
        if not s:
            return Result(401, {"error": "login required"})
        expires = s.expires_at
        if s.invite_id is None and s.expires_at - self.now() < self.cfg.renew_days * 86400:
            expires = self.now() + self.cfg.session_days * 86400
            self.store.touch_session(s.id, self.now(), expires)
        else:
            self.store.touch_session(s.id, self.now())
        # The cookie goes back on every call, carrying whatever the row now says -- same token,
        # current life. A passkey session that just renewed above needs it. So does a guest whose
        # invite was extended after their cookie was written: the row says they have another week,
        # but their browser was told a date, and this is the only thing that ever revises it.
        cookie = self.cookie(token, int(expires - self.now()))
        return Result(200, {"name": u.name, "role": u.role, "expires": int(expires), **self._sites_out(u)}, cookie=cookie)

    def logout(self, token) -> Result:
        s, _ = self._session(token)
        if s:
            self.store.revoke_session(s.id, self.now())
        return Result(200, {"ok": True}, cookie=self.clear_cookie())

    # ---------- passkey login ----------
    def login_options(self, client_key: str) -> Result:
        # This route needs no session and writes a challenge row on every call, and an abandoned
        # ceremony's row is only ever reclaimed by the sweep -- so it gets a ceiling of its own, or a
        # stranger can grow the database at will and sit on the store's single lock while doing it.
        # Every call counts here, not just failures: there is no such thing as a failed options call.
        key = f"options:{client_key}"
        if self._blocked(key, OPTIONS_LIMIT):
            return Result(429, {"error": "too many tries. wait a bit."})
        self.store.note_failure(key, self.now(), RATE_WINDOW)
        challenge, options = passkeys.authentication_options(self.cfg)
        cid = self.store.create_challenge("login", challenge, self.now() + CHALLENGE_TTL)
        return Result(200, {"challenge_id": cid, "options": json.loads(options)})

    def login_verify(self, challenge_id, credential, user_agent: str, client_key: str) -> Result:
        key = f"login:{client_key}"
        if self._blocked(key):
            return Result(429, {"error": "too many tries. wait a bit."})
        row = self.store.take_challenge(challenge_id or "", "login", self.now())
        if not row or not isinstance(credential, dict):
            return self._fail(key)
        try:
            cred = self.store.credential_by_id(passkeys.credential_id_bytes(credential))
            user = self.store.user_by_id(cred.user_id) if cred else None
            if not cred or not user or user.disabled:
                return self._fail(key)
            count, counter_warning = passkeys.verify_authentication(self.cfg, credential, bytes(row["challenge"]), cred.public_key, cred.sign_count)
        except Exception:
            return self._fail(key)
        if counter_warning:
            # Not fatal -- synced passkeys keep no counter -- but it is the only clone signal WebAuthn
            # offers, so it goes in the log with enough to act on: who, which key, and both counts.
            print(f"sign counter did not advance for {user.name}: credential {cred.id} ({cred.label or 'no label'}) "
                  f"stored {cred.sign_count}, presented {count}", flush=True)
        # Never lower a stored counter: writing a regressed value back would make the next assertion
        # look like an advance, and a credential that once went backwards would never warn again.
        self.store.touch_credential(cred.id, max(count, cred.sign_count), self.now())
        self.store.clear_failures(key)
        return self._start_session(user, None, self.now() + self.cfg.session_days * 86400, user_agent)

    # ---------- invites ----------
    def redeem(self, code: str, user_agent: str, client_key: str) -> Result:
        key = f"invite:{client_key}"
        if self._blocked(key):
            return Result(429, {"error": "too many tries. wait a bit."})
        now = self.now()
        inv = self.store.invite_by_code(normalize(code or ""))
        if not inv or inv.consumed_at is not None or inv.expires_at <= now:
            return self._fail(key)
        user = self.store.user_by_id(inv.user_id)
        if not user or user.disabled:
            return self._fail(key)
        # Nothing here clears the failure counter. A working code is not evidence that the tries around
        # it were honest: one legitimate invite would otherwise buy its holder an unlimited number of
        # guesses, nine wrong ones at a time, against the ~30 bits an invite code is worth. Somebody
        # typing a code they were handed does not accumulate ten failures in five minutes, so nothing
        # legitimate is throttled by leaving the count alone. (The reset in login_verify stays: it takes
        # a working passkey, which already grants everything the reset could buy.)
        if inv.kind == "guest":
            if not self.store.claim_invite_browser(inv.id):
                return self._fail(key, 403, "this invite is full. ask JC.")
            return self._start_session(user, inv.id, inv.expires_at, user_agent)
        self.store.clear_challenges("enroll", inv.id)
        ticket = self.store.create_challenge("enroll", b"", now + ENROLL_TTL, user_id=user.id, invite_id=inv.id)
        return Result(200, {"kind": inv.kind, "name": user.name, "ticket": ticket})

    def create_invite(self, name, site_names, ttl, kind) -> Result:
        name = (name or "").strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,23}", name):
            return Result(400, {"error": "name: letters, digits, - or _, up to 24, starting with a letter"})
        if kind not in ("guest", "member"):
            return Result(400, {"error": "kind must be guest or member"})
        try:
            hosts = self._hosts_from_names(site_names)
            ttl_seconds = parse_ttl(ttl)
        except ValueError as e:
            return Result(400, {"error": str(e)})
        if not hosts:
            return Result(400, {"error": "give at least one site"})
        now = self.now()
        user = self.store.user_by_name(name)
        if user and user.role == "owner":
            return Result(400, {"error": "that name is taken"})
        if user and user.role != kind:
            return Result(400, {"error": f"{name} is a {user.role}; pick another name or revoke first"})
        if user:
            self.store.set_sites(user.id, sorted(set(user.sites) | set(hosts)))
            self.store.set_disabled(user.id, False)
            user = self.store.user_by_id(user.id)
        else:
            user = self.store.create_user(name, kind, hosts, now)
        code = new_code()
        inv = self.store.create_invite(code, user.id, kind, now + ttl_seconds, now, max_browsers=3 if kind == "guest" else 1)
        return Result(200, {"name": name, "kind": kind, "code": code, "link": self._invite_link(code, user),
                            "expires": int(inv.expires_at), **self._sites_out(user)})

    def enroll_owner(self) -> Result:
        """CLI only. First passkey, and the recovery path: a fresh enrollment code for the owner, good for 15 minutes."""
        now = self.now()
        user = self.store.user_by_name(self.cfg.owner_name) or self.store.create_user(self.cfg.owner_name, "owner", ["*"], now)
        code = new_code()
        inv = self.store.create_invite(code, user.id, "owner", now + ENROLL_TTL, now, max_browsers=1)
        return Result(200, {"name": user.name, "code": code, "link": self._invite_link(code, user), "expires": int(inv.expires_at)})

    # ---------- registration: enrolling from an invite, or adding a key to a passkey session ----------
    def _enrolling_user(self, ticket, token):
        if ticket:
            row = self.store.peek_challenge(ticket, "enroll", self.now())
            if not row:
                return None, None
            inv = self.store.invite_by_id(row["invite_id"])
            if not inv or inv.consumed_at is not None or inv.expires_at <= self.now():
                return None, None
            return self.store.user_by_id(row["user_id"]), row
        s, u = self._session(token)
        if not s or s.invite_id is not None:
            return None, None
        return u, None

    def register_options(self, ticket, token) -> Result:
        user, _ = self._enrolling_user(ticket, token)
        if not user:
            return Result(401, {"error": "permission denied"})
        exclude = [c.credential_id for c in self.store.credentials_for(user.id)]
        challenge, options = passkeys.registration_options(self.cfg, str(user.id).encode(), user.name, exclude)
        cid = self.store.create_challenge("register", challenge, self.now() + CHALLENGE_TTL, user_id=user.id)
        return Result(200, {"challenge_id": cid, "options": json.loads(options)})

    def register_verify(self, challenge_id, credential, ticket, token, user_agent: str, label: str = "") -> Result:
        user, enroll = self._enrolling_user(ticket, token)
        row = self.store.take_challenge(challenge_id or "", "register", self.now())
        if not user or not row or row["user_id"] != user.id or not isinstance(credential, dict):
            return Result(401, {"error": "permission denied"})
        try:
            cred_id, public_key, count = passkeys.verify_registration(self.cfg, credential, bytes(row["challenge"]))
        except Exception:
            return Result(401, {"error": "that key didn't verify"})
        # An enrollment writes nothing until it has won the invite: verifying the key persists nothing, so a
        # request that loses the claim here leaves no credential, no session, and no consumed state of its own.
        if enroll and not self.store.consume_invite(enroll["invite_id"], self.now()):
            return Result(401, {"error": "permission denied"})
        transports = ",".join(credential.get("response", {}).get("transports", []) or [])
        self.store.add_credential(user.id, cred_id, public_key, count, transports, (label or "")[:40], self.now())
        if enroll:
            self.store.take_challenge(ticket, "enroll", self.now())
            return self._start_session(user, None, self.now() + self.cfg.session_days * 86400, user_agent)
        return Result(200, {"ok": True, "passkeys": len(self.store.credentials_for(user.id))})

    # ---------- owner admin ----------
    def admin_guests(self, token) -> Result:
        if not self._owner(token):
            return Result(403, {"error": "owner only"})
        now, out = self.now(), []
        for u in self.store.all_users():
            if u.role == "owner":
                continue
            invites = [{"kind": i.kind, "expires": int(i.expires_at), "browsers_used": i.browsers_used, "max_browsers": i.max_browsers,
                        "consumed": i.consumed_at is not None, "active": i.consumed_at is None and i.expires_at > now} for i in self.store.invites_for(u.id)]
            sessions = [{"created": int(s.created_at), "last_seen": int(s.last_seen_at), "expires": int(s.expires_at), "user_agent": s.user_agent}
                        for s in self.store.sessions_for(u.id, now)]
            out.append({"name": u.name, "role": u.role, "disabled": u.disabled, "passkeys": len(self.store.credentials_for(u.id)),
                        "invites": invites, "sessions": sessions, **self._sites_out(u)})
        return Result(200, {"guests": out})

    def admin_invite(self, token, name, sites, ttl, kind) -> Result:
        if not self._owner(token):
            return Result(403, {"error": "owner only"})
        return self.create_invite(name, sites, ttl, kind or "guest")

    def admin_revoke(self, token, name, keys: bool = False) -> Result:
        if not self._owner(token):
            return Result(403, {"error": "owner only"})
        u = self.store.user_by_name((name or "").strip().lower())
        if not u or u.role == "owner":
            return Result(404, {"error": "no such guest"})
        now = self.now()
        self.store.revoke_sessions_for(u.id, now)
        self.store.expire_invites_for(u.id, now)
        self.store.set_disabled(u.id, True)
        drop_keys = (keys is True) or u.role == "guest"
        if drop_keys:
            self.store.remove_credentials_for(u.id)
        return Result(200, {"ok": True, "name": u.name, "keys_removed": drop_keys})

    def admin_sites(self, token, name, grant=(), deny=()) -> Result:
        if not self._owner(token):
            return Result(403, {"error": "owner only"})
        u = self.store.user_by_name((name or "").strip().lower())
        if not u or u.role == "owner":
            return Result(404, {"error": "no such guest"})
        try:
            add, drop = set(self._hosts_from_names(grant)), set(self._hosts_from_names(deny))
        except ValueError as e:
            return Result(400, {"error": str(e)})
        self.store.set_sites(u.id, sorted((set(u.sites) | add) - drop))
        if add:
            self.store.set_disabled(u.id, False)
        u = self.store.user_by_id(u.id)
        return Result(200, {"name": u.name, "role": u.role, **self._sites_out(u)})

    def admin_extend(self, token, name, ttl) -> Result:
        """Give someone longer without sending them anything. Their invite and every live session
           move to the same date, so an existing browser simply keeps working -- which is the
           difference between this and inviting them again, which mints a code they must redeem."""
        if not self._owner(token):
            return Result(403, {"error": "owner only"})
        u = self.store.user_by_name((name or "").strip().lower())
        if not u or u.role == "owner":
            return Result(404, {"error": "no such guest"})
        if u.disabled:
            return Result(400, {"error": f"{u.name} is revoked. invite them again to let them back in."})
        try:
            until = self.now() + parse_ttl(ttl)
        except ValueError as e:
            return Result(400, {"error": str(e)})
        now = self.now()
        live_invites = [i for i in self.store.invites_for(u.id) if i.consumed_at is None and i.expires_at > now]
        live_sessions = self.store.sessions_for(u.id, now)
        if not live_invites and not live_sessions:
            return Result(400, {"error": f"{u.name} has nothing running to extend. invite them again."})
        moved = sum(1 for i in live_invites if self.store.extend_invite(i.id, until, now))
        moved += self.store.extend_sessions_for(u.id, until, now)
        # Read the deadline back rather than reporting the one asked for: extending only ever moves
        # a date forward, so someone who already had longer keeps it and should be told that date.
        after = [i.expires_at for i in self.store.invites_for(u.id) if i.consumed_at is None and i.expires_at > now]
        after += [ss.expires_at for ss in self.store.sessions_for(u.id, now)]
        return Result(200, {"name": u.name, "expires": int(max(after)), "moved": moved})

    def passkeys_list(self, token) -> Result:
        s, u = self._session(token)
        if not s or s.invite_id is not None:
            return Result(403, {"error": "passkey sessions only"})
        return Result(200, {"passkeys": [{"id": c.id, "label": c.label, "created": int(c.created_at), "last_used": int(c.last_used_at or 0)}
                                         for c in self.store.credentials_for(u.id)]})

    def passkeys_remove(self, token, cred_id) -> Result:
        s, u = self._session(token)
        if not s or s.invite_id is not None:
            return Result(403, {"error": "passkey sessions only"})
        if len(self.store.credentials_for(u.id)) <= 1:
            return Result(400, {"error": "that's your last key. add another first."})
        removed = self.store.remove_credential(u.id, int(cred_id)) if str(cred_id).isdigit() else 0
        return Result(200, {"ok": True}) if removed else Result(404, {"error": "no such key"})
