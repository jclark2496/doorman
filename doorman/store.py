"""SQLite behind the service. One connection, one lock (the HTTP server is threaded).
Secrets never land here in the clear: session tokens and invite codes are stored as SHA-256 digests."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, role TEXT NOT NULL, sites_json TEXT NOT NULL,
  created_at REAL NOT NULL, disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), credential_id BLOB UNIQUE NOT NULL,
  public_key BLOB NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, last_used_at REAL);
CREATE TABLE IF NOT EXISTS invites (
  id INTEGER PRIMARY KEY, code_hash TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL,
  expires_at REAL NOT NULL, max_browsers INTEGER NOT NULL DEFAULT 3, browsers_used INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL, consumed_at REAL);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id),
  invite_id INTEGER REFERENCES invites(id), created_at REAL NOT NULL, last_seen_at REAL NOT NULL, expires_at REAL NOT NULL,
  user_agent TEXT NOT NULL DEFAULT '', revoked_at REAL);
CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, user_id INTEGER, invite_id INTEGER, challenge BLOB NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, window_start REAL NOT NULL, count INTEGER NOT NULL);
"""


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class User:
    id: int; name: str; role: str; sites: list; disabled: bool


@dataclass
class Credential:
    id: int; user_id: int; credential_id: bytes; public_key: bytes; sign_count: int; transports: str; label: str; created_at: float; last_used_at: float | None


@dataclass
class Invite:
    id: int; user_id: int; kind: str; expires_at: float; max_browsers: int; browsers_used: int; created_at: float; consumed_at: float | None


@dataclass
class Session:
    id: int; token_hash: str; user_id: int; invite_id: int | None; created_at: float; last_seen_at: float; expires_at: float; user_agent: str; revoked_at: float | None


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    # -- plumbing --
    def _one(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).fetchone()

    def _all(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def _run(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).lastrowid

    def _change(self, sql, args=()):
        """Like _run, but answers how many rows the statement actually touched -- which is the
           whole point of the conditional UPDATEs below, where the WHERE clause is the guard."""
        with self.lock:
            return self.conn.execute(sql, args).rowcount

    # -- users --
    @staticmethod
    def _user(r):
        return User(r["id"], r["name"], r["role"], json.loads(r["sites_json"]), bool(r["disabled"])) if r else None

    def create_user(self, name: str, role: str, sites: list, now: float) -> User:
        uid = self._run("INSERT INTO users(name, role, sites_json, created_at) VALUES(?,?,?,?)", (name, role, json.dumps(sorted(set(sites))), now))
        return self.user_by_id(uid)

    def user_by_name(self, name: str) -> User | None:
        return self._user(self._one("SELECT * FROM users WHERE name=?", (name,)))

    def user_by_id(self, uid: int) -> User | None:
        return self._user(self._one("SELECT * FROM users WHERE id=?", (uid,)))

    def all_users(self) -> list:
        return [self._user(r) for r in self._all("SELECT * FROM users ORDER BY created_at, id")]

    def set_sites(self, uid: int, sites: list) -> None:
        self._run("UPDATE users SET sites_json=? WHERE id=?", (json.dumps(sorted(set(sites))), uid))

    def set_disabled(self, uid: int, flag: bool) -> None:
        self._run("UPDATE users SET disabled=? WHERE id=?", (1 if flag else 0, uid))

    # -- credentials --
    @staticmethod
    def _cred(r):
        return Credential(r["id"], r["user_id"], bytes(r["credential_id"]), bytes(r["public_key"]), r["sign_count"], r["transports"], r["label"], r["created_at"], r["last_used_at"]) if r else None

    def add_credential(self, uid: int, credential_id: bytes, public_key: bytes, sign_count: int, transports: str, label: str, now: float) -> Credential:
        cid = self._run("INSERT INTO credentials(user_id, credential_id, public_key, sign_count, transports, label, created_at) VALUES(?,?,?,?,?,?,?)",
                        (uid, credential_id, public_key, sign_count, transports, label, now))
        return self._cred(self._one("SELECT * FROM credentials WHERE id=?", (cid,)))

    def credential_by_id(self, credential_id: bytes) -> Credential | None:
        return self._cred(self._one("SELECT * FROM credentials WHERE credential_id=?", (credential_id,)))

    def credentials_for(self, uid: int) -> list:
        return [self._cred(r) for r in self._all("SELECT * FROM credentials WHERE user_id=? ORDER BY created_at, id", (uid,))]

    def touch_credential(self, cid: int, sign_count: int, now: float) -> None:
        self._run("UPDATE credentials SET sign_count=?, last_used_at=? WHERE id=?", (sign_count, now, cid))

    def remove_credential(self, uid: int, cid: int) -> int:
        with self.lock:
            return self.conn.execute("DELETE FROM credentials WHERE id=? AND user_id=?", (cid, uid)).rowcount

    def remove_credentials_for(self, uid: int) -> None:
        self._run("DELETE FROM credentials WHERE user_id=?", (uid,))

    # -- invites --
    @staticmethod
    def _inv(r):
        return Invite(r["id"], r["user_id"], r["kind"], r["expires_at"], r["max_browsers"], r["browsers_used"], r["created_at"], r["consumed_at"]) if r else None

    def create_invite(self, code: str, uid: int, kind: str, expires_at: float, now: float, max_browsers: int = 3) -> Invite:
        iid = self._run("INSERT INTO invites(code_hash, user_id, kind, expires_at, max_browsers, created_at) VALUES(?,?,?,?,?,?)",
                        (digest(code), uid, kind, expires_at, max_browsers, now))
        return self.invite_by_id(iid)

    def invite_by_id(self, iid: int) -> Invite | None:
        return self._inv(self._one("SELECT * FROM invites WHERE id=?", (iid,)))

    def invite_by_code(self, code: str) -> Invite | None:
        return self._inv(self._one("SELECT * FROM invites WHERE code_hash=?", (digest(code),)))

    def invites_for(self, uid: int) -> list:
        return [self._inv(r) for r in self._all("SELECT * FROM invites WHERE user_id=? ORDER BY created_at, id", (uid,))]

    def claim_invite_browser(self, iid: int) -> bool:
        with self.lock:
            return self.conn.execute("UPDATE invites SET browsers_used=browsers_used+1 WHERE id=? AND browsers_used<max_browsers", (iid,)).rowcount == 1

    def consume_invite(self, iid: int, now: float) -> bool:
        with self.lock:
            return self.conn.execute("UPDATE invites SET consumed_at=? WHERE id=? AND consumed_at IS NULL", (now, iid)).rowcount == 1

    def extend_invite(self, iid: int, expires_at: float, now: float) -> bool:
        """Push one live invite's deadline later. The WHERE clause is the whole guard: a consumed
           invite, an already-dead one, and one that already runs past `expires_at` are all left
           alone, so extending can only ever move a deadline forward and can never resurrect."""
        return self._change(
            "UPDATE invites SET expires_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>? AND expires_at<?",
            (expires_at, iid, now, expires_at)) == 1

    def extend_sessions_for(self, uid: int, expires_at: float, now: float) -> int:
        """The same, for every live session a person holds. Returns how many moved."""
        return self._change(
            "UPDATE sessions SET expires_at=? WHERE user_id=? AND revoked_at IS NULL AND expires_at>? AND expires_at<?",
            (expires_at, uid, now, expires_at))

    def expire_invites_for(self, uid: int, now: float) -> None:
        self._run("UPDATE invites SET expires_at=? WHERE user_id=? AND expires_at>?", (now, uid, now))

    # -- sessions --
    @staticmethod
    def _sess(r):
        return Session(r["id"], r["token_hash"], r["user_id"], r["invite_id"], r["created_at"], r["last_seen_at"], r["expires_at"], r["user_agent"], r["revoked_at"]) if r else None

    def create_session(self, token: str, uid: int, invite_id: int | None, expires_at: float, user_agent: str, now: float) -> Session:
        sid = self._run("INSERT INTO sessions(token_hash, user_id, invite_id, created_at, last_seen_at, expires_at, user_agent) VALUES(?,?,?,?,?,?,?)",
                        (digest(token), uid, invite_id, now, now, expires_at, (user_agent or "")[:200]))
        return self._sess(self._one("SELECT * FROM sessions WHERE id=?", (sid,)))

    def session_by_token(self, token: str | None) -> Session | None:
        if not token:
            return None
        return self._sess(self._one("SELECT * FROM sessions WHERE token_hash=?", (digest(token),)))

    def touch_session(self, sid: int, now: float, expires_at: float | None = None) -> None:
        if expires_at is None:
            self._run("UPDATE sessions SET last_seen_at=? WHERE id=?", (now, sid))
        else:
            self._run("UPDATE sessions SET last_seen_at=?, expires_at=? WHERE id=?", (now, expires_at, sid))

    def revoke_session(self, sid: int, now: float) -> None:
        self._run("UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (now, sid))

    def revoke_sessions_for(self, uid: int, now: float) -> None:
        self._run("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now, uid))

    def revoke_all_sessions(self, now: float) -> None:
        self._run("UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL", (now,))

    def sessions_for(self, uid: int, now: float) -> list:
        return [self._sess(r) for r in self._all("SELECT * FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at>? ORDER BY created_at, id", (uid, now))]

    # -- challenges: login and register challenges are five minutes and single use (take_challenge);
    #    enrollment tickets live fifteen and are deliberately read without being consumed (peek_challenge),
    #    because the ticket has to survive register/options and register/verify --
    def create_challenge(self, kind: str, challenge: bytes, expires_at: float, user_id: int | None = None, invite_id: int | None = None) -> str:
        cid = secrets.token_urlsafe(24)
        self._run("INSERT INTO challenges(id, kind, user_id, invite_id, challenge, expires_at) VALUES(?,?,?,?,?,?)", (cid, kind, user_id, invite_id, challenge, expires_at))
        return cid

    def peek_challenge(self, cid: str, kind: str, now: float) -> dict | None:
        r = self._one("SELECT * FROM challenges WHERE id=? AND kind=? AND expires_at>?", (cid, kind, now))
        return dict(r) if r else None

    def take_challenge(self, cid: str, kind: str, now: float) -> dict | None:
        with self.lock:
            r = self.peek_challenge(cid, kind, now)
            if r:
                self.conn.execute("DELETE FROM challenges WHERE id=?", (cid,))
            return r

    def clear_challenges(self, kind: str, invite_id: int) -> None:
        self._run("DELETE FROM challenges WHERE kind=? AND invite_id=?", (kind, invite_id))

    def purge(self, now: float) -> None:
        self._run("DELETE FROM challenges WHERE expires_at<=?", (now,))
        self._run("DELETE FROM attempts WHERE window_start<=?", (now - 3600,))

    # -- failed attempts per key, in a sliding window --
    def failures(self, key: str, now: float, window: int) -> int:
        r = self._one("SELECT * FROM attempts WHERE key=?", (key,))
        if not r or r["window_start"] + window <= now:
            return 0
        return r["count"]

    def note_failure(self, key: str, now: float, window: int) -> None:
        with self.lock:
            r = self.conn.execute("SELECT * FROM attempts WHERE key=?", (key,)).fetchone()
            if not r or r["window_start"] + window <= now:
                self.conn.execute("INSERT OR REPLACE INTO attempts(key, window_start, count) VALUES(?,?,1)", (key, now))
            else:
                self.conn.execute("UPDATE attempts SET count=count+1 WHERE key=?", (key,))

    def clear_failures(self, key: str) -> None:
        self._run("DELETE FROM attempts WHERE key=?", (key,))
