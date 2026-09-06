#!/usr/bin/env python3
"""doorman — one login for every site you own.

  doorman.py serve                 run the service (systemd does this)
  doorman.py enroll-owner          print a one-time enrollment link for the owner's passkey (first key, or recovery)
  doorman.py list                  users, roles, keys, live sessions
  doorman.py revoke <name> [--keys]
  doorman.py revoke-all-sessions   everyone logs in again
"""
from __future__ import annotations

import sys
import time

from doorman.config import Config
from doorman.http import serve
from doorman.service import AuthService
from doorman.store import Store


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "serve"
    if cmd == "serve":
        return serve()
    # Recognize the command shape before touching the store, so an unknown command (or a
    # malformed one, like `revoke` with no name) can explain itself even with no database yet.
    if cmd not in ("enroll-owner", "list", "revoke-all-sessions") and not (cmd == "revoke" and len(argv) > 2):
        sys.exit(__doc__)
    cfg = Config.from_env()
    svc = AuthService(cfg, Store(cfg.db_path))
    now = time.time()
    if cmd == "enroll-owner":
        r = svc.enroll_owner()
        print("open this within 15 minutes on the device that will hold the passkey:")
        print(r.body["link"])
        print(f"or type the code at the password prompt: {r.body['code']}")
    elif cmd == "list":
        for u in svc.store.all_users():
            sites = "*" if u.role == "owner" else ",".join(u.sites)
            print(f"{u.name:16} {u.role:7} {'disabled' if u.disabled else 'active':9} keys={len(svc.store.credentials_for(u.id))} sessions={len(svc.store.sessions_for(u.id, now))} sites={sites}")
    elif cmd == "revoke":
        u = svc.store.user_by_name(argv[2])
        if not u:
            sys.exit(f"no such user: {argv[2]}")
        svc.store.revoke_sessions_for(u.id, now)
        svc.store.expire_invites_for(u.id, now)
        if "--keys" in argv or u.role == "guest":
            svc.store.remove_credentials_for(u.id)
        if u.role != "owner":
            svc.store.set_disabled(u.id, True)
        print(f"revoked {u.name}")
    elif cmd == "revoke-all-sessions":
        svc.store.revoke_all_sessions(now)
        print("every session is gone. everyone logs in again.")


if __name__ == "__main__":
    main(sys.argv)
