import sqlite3, tempfile, unittest
from pathlib import Path
from doorman.store import Store, digest


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.path = str(Path(self.tmp.name) / "auth.db"); self.s = Store(self.path)
    def tearDown(self): self.s.close(); self.tmp.cleanup()

    def test_users_round_trip_and_sites_are_sorted_unique(self):
        u = self.s.create_user("jill", "member", ["photos.example.com", "notes.example.com", "photos.example.com"], 100.0)
        self.assertEqual((u.name, u.role, u.disabled), ("jill", "member", False))
        self.assertEqual(u.sites, ["notes.example.com", "photos.example.com"])
        self.assertEqual(self.s.user_by_name("jill").id, u.id)
        self.s.set_disabled(u.id, True); self.assertTrue(self.s.user_by_id(u.id).disabled)

    def test_invite_codes_and_session_tokens_are_stored_hashed(self):
        u = self.s.create_user("bob", "guest", ["notes.example.com"], 1.0)
        inv = self.s.create_invite("coral-lounger-42", u.id, "guest", 1000.0, 1.0)
        sess = self.s.create_session("tok-secret", u.id, inv.id, 1000.0, "Safari", 1.0)
        raw = sqlite3.connect(self.path)
        for table in ("invites", "sessions"):
            blob = " ".join(str(v) for row in raw.execute(f"SELECT * FROM {table}") for v in row)
            self.assertNotIn("coral-lounger-42", blob); self.assertNotIn("tok-secret", blob)
        raw.close()
        self.assertEqual(self.s.invite_by_code("coral-lounger-42").id, inv.id)
        self.assertEqual(self.s.session_by_token("tok-secret").id, sess.id)
        self.assertIsNone(self.s.session_by_token("nope")); self.assertIsNone(self.s.session_by_token(None))
        self.assertEqual(len(digest("x")), 64)

    def test_invite_consumption_and_expiry(self):
        # Browser counting is not exercised here on purpose: claim_invite_browser is the only way to
        # move that counter, and it is pinned against the cap in test_service_invites.py.
        u = self.s.create_user("bob", "guest", ["notes.example.com"], 1.0)
        inv = self.s.create_invite("a-b-c-01", u.id, "guest", 500.0, 1.0)
        self.s.consume_invite(inv.id, 7.0); self.assertEqual(self.s.invite_by_id(inv.id).consumed_at, 7.0)
        self.s.expire_invites_for(u.id, 9.0); self.assertEqual(self.s.invite_by_id(inv.id).expires_at, 9.0)

    def test_sessions_revoke_touch_and_listing(self):
        u = self.s.create_user("ada", "owner", ["*"], 1.0)
        a = self.s.create_session("t1", u.id, None, 100.0, "", 1.0); b = self.s.create_session("t2", u.id, None, 100.0, "", 1.0)
        self.assertEqual([x.id for x in self.s.sessions_for(u.id, 50.0)], [a.id, b.id])
        self.s.touch_session(a.id, 20.0, 300.0); a2 = self.s.session_by_token("t1"); self.assertEqual((a2.last_seen_at, a2.expires_at), (20.0, 300.0))
        self.s.revoke_session(b.id, 30.0); self.assertEqual(self.s.session_by_token("t2").revoked_at, 30.0)
        self.assertEqual([x.id for x in self.s.sessions_for(u.id, 50.0)], [a.id])
        self.s.revoke_all_sessions(40.0); self.assertEqual(self.s.sessions_for(u.id, 50.0), [])

    def test_challenges_are_single_use_and_expire(self):
        cid = self.s.create_challenge("login", b"\x01\x02", 100.0)
        self.assertEqual(bytes(self.s.peek_challenge(cid, "login", 50.0)["challenge"]), b"\x01\x02")
        self.assertIsNone(self.s.take_challenge(cid, "register", 50.0))
        self.assertIsNotNone(self.s.take_challenge(cid, "login", 50.0))
        self.assertIsNone(self.s.take_challenge(cid, "login", 50.0))
        late = self.s.create_challenge("login", b"x", 100.0); self.assertIsNone(self.s.take_challenge(late, "login", 200.0))

    def test_credentials(self):
        u = self.s.create_user("ada", "owner", ["*"], 1.0)
        c = self.s.add_credential(u.id, b"cred-1", b"pk", 0, "internal", "iphone", 1.0)
        self.assertEqual(self.s.credential_by_id(b"cred-1").id, c.id)
        self.s.touch_credential(c.id, 5, 9.0); self.assertEqual((self.s.credential_by_id(b"cred-1").sign_count, self.s.credential_by_id(b"cred-1").last_used_at), (5, 9.0))
        self.assertEqual(self.s.remove_credential(u.id + 1, c.id), 0); self.assertEqual(self.s.remove_credential(u.id, c.id), 1)
        self.assertEqual(self.s.credentials_for(u.id), [])

    def test_failure_window(self):
        self.assertEqual(self.s.failures("k", 0.0, 300), 0)
        for _ in range(3): self.s.note_failure("k", 10.0, 300)
        self.assertEqual(self.s.failures("k", 100.0, 300), 3)
        self.assertEqual(self.s.failures("k", 400.0, 300), 0)
        self.s.note_failure("k", 400.0, 300); self.assertEqual(self.s.failures("k", 401.0, 300), 1)
        self.s.clear_failures("k"); self.assertEqual(self.s.failures("k", 401.0, 300), 0)
