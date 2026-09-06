"""HTTP in, AuthService out. Nothing in here decides anything."""
from __future__ import annotations

import ipaddress
import json
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import Config
from .service import AuthService, Result
from .store import Store

MAX_BODY = 64 * 1024
PURGE_EVERY = 300      # seconds between housekeeping sweeps


def make_handler(svc: AuthService):
    cfg = svc.cfg

    class Handler(BaseHTTPRequestHandler):
        server_version = "SandalsAuth/1.0"
        timeout = 15   # seconds; no single connection may hold a thread longer than this, whatever the cause

        def version_string(self) -> str:   # server name only; never the interpreter's patch version
            return self.server_version

        def log_message(self, fmt, *args):      # audit line: rate-limit key, request line, status, and (when known) the resolved user; never tokens or codes
            who = getattr(self, "_audit_user", None)
            print(f"{self.client_key()} - {fmt % args}" + (f" user={who}" if who else ""), flush=True)

        # -- request helpers --
        def client_key(self) -> str:
            peer = str(self.client_address[0])
            hops = [h.strip() for h in self.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
            if peer in ("127.0.0.1", "::1") and hops:
                # Caddy is configured with no trusted_proxies (see the runbook), so it never appends to a
                # client-supplied X-Forwarded-For — it discards whatever the client sent and writes only
                # its own value, so the header we see here is Caddy's value alone, not a chain. We still
                # take the *last* entry rather than assume there's exactly one, so this keeps working
                # unchanged if trusted_proxies is ever configured and Caddy starts appending after the
                # client's value instead of replacing it.
                try:
                    return str(ipaddress.ip_address(hops[-1]))
                except ValueError:
                    pass
            return peer

        def token(self):
            morsel = SimpleCookie(self.headers.get("Cookie", "")).get(cfg.cookie_name)
            return morsel.value if morsel else None

        def body(self):
            if "Transfer-Encoding" in self.headers:
                return None   # chunked bodies have no Content-Length to police; refuse outright
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                return None   # a header that doesn't parse as an integer is refused, not raised
            if length < 0 or length > MAX_BODY:
                return None   # negative would otherwise read until the connection closes
            raw = self.rfile.read(length) if length else b""
            try:
                return json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                return None

        def same_origin(self) -> bool:
            return self.headers.get("Origin", "") == cfg.origin and self.headers.get("X-Doorman-Request", "") == "1"

        def send(self, r: Result):
            self._audit_user = r.headers.get("X-Doorman-User") or (r.body or {}).get("name")
            payload = b"" if r.redirect else json.dumps(r.body or {}).encode("utf-8")
            self.send_response(r.status)
            for k, v in r.headers.items():
                self.send_header(k, v)
            if r.redirect:
                self.send_header("Location", r.redirect)
            if r.cookie:
                self.send_header("Set-Cookie", r.cookie)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if payload:
                self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload and self.command != "HEAD":
                self.wfile.write(payload)

        # -- routes --
        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/_auth/health":
                return self.send(Result(200, {"ok": True}))
            if path == "/_auth/verify":
                host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").split(",")[0].split(":")[0].strip().lower()
                return self.send(svc.verify(self.token(), host, self.headers.get("X-Forwarded-Method", "GET"),
                                            self.headers.get("X-Forwarded-Uri", "/"), self.headers.get("Accept", "")))
            if path == "/_auth/me":
                return self.send(svc.me(self.token()))
            if path == "/_auth/admin/guests":
                return self.send(svc.admin_guests(self.token()))
            if path == "/_auth/admin/passkeys":
                return self.send(svc.passkeys_list(self.token()))
            self.send(Result(404, {"error": "no such path"}))

        def do_HEAD(self):
            self.do_GET()

        def do_POST(self):
            path = urlparse(self.path).path
            if not self.same_origin():
                return self.send(Result(403, {"error": "cross-site request refused"}))
            b = self.body()
            if not isinstance(b, dict):
                return self.send(Result(400, {"error": "bad json"}))
            ua, tok, key = self.headers.get("User-Agent", ""), self.token(), self.client_key()
            if path == "/_auth/login/options":
                return self.send(svc.login_options(key))
            if path == "/_auth/login/verify":
                return self.send(svc.login_verify(b.get("challenge_id"), b.get("credential"), ua, key))
            if path == "/_auth/invite/redeem":
                return self.send(svc.redeem(str(b.get("code", "")), ua, key))
            if path == "/_auth/register/options":
                return self.send(svc.register_options(b.get("ticket"), tok))
            if path == "/_auth/register/verify":
                return self.send(svc.register_verify(b.get("challenge_id"), b.get("credential"), b.get("ticket"), tok, ua, str(b.get("label", ""))))
            if path == "/_auth/logout":
                return self.send(svc.logout(tok))
            if path == "/_auth/admin/invite":
                sites = b.get("sites")
                if sites is not None and not isinstance(sites, list):
                    return self.send(Result(400, {"error": "bad json"}))
                return self.send(svc.admin_invite(tok, b.get("name"), sites, b.get("ttl"), b.get("kind")))
            if path == "/_auth/admin/revoke":
                # Only a genuine JSON `true` may drop someone's passkeys; any other value (including the
                # string "false", which Python's bool() would call truthy) is treated as false.
                return self.send(svc.admin_revoke(tok, b.get("name"), b.get("keys") is True))
            if path == "/_auth/admin/sites":
                grant, deny = b.get("grant"), b.get("deny")
                if (grant is not None and not isinstance(grant, list)) or (deny is not None and not isinstance(deny, list)):
                    return self.send(Result(400, {"error": "bad json"}))
                return self.send(svc.admin_sites(tok, b.get("name"), grant or [], deny or []))
            if path == "/_auth/admin/extend":
                return self.send(svc.admin_extend(tok, b.get("name"), b.get("ttl")))
            if path == "/_auth/admin/passkeys":
                return self.send(svc.passkeys_remove(tok, b.get("remove")))
            self.send(Result(404, {"error": "no such path"}))

    return Handler


def sweep(store, now: float) -> None:
    """One housekeeping pass: expired challenges and stale attempt counters. Rows are otherwise only
    removed when someone completes the ceremony they belong to, so an abandoned one stays forever.
    A pass that raises (a locked database, say) costs that pass and nothing else -- the service keeps
    serving and the next sweep runs on schedule."""
    try:
        store.purge(now)
    except Exception as exc:
        print(f"purge failed: {exc.__class__.__name__}: {exc}", flush=True)


def _sweeper(store, interval: int = PURGE_EVERY) -> None:
    while True:
        time.sleep(interval)
        sweep(store, time.time())


def serve(cfg: Config | None = None):
    cfg = cfg or Config.from_env()
    store = Store(cfg.db_path)
    svc = AuthService(cfg, store)
    # Daemon, so it can never hold the process open on shutdown; guarded, so it can never bring it down.
    threading.Thread(target=_sweeper, args=(store,), name="purge", daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", cfg.port), make_handler(svc))
    print(f"doorman listening on 127.0.0.1:{cfg.port}", flush=True)
    httpd.serve_forever()
