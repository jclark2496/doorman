import tempfile, unittest
from pathlib import Path
from doorman.config import Config
from doorman.service import AuthService
from doorman.store import Store
from tests.softauth import SoftAuthenticator

CFG = Config.from_env({}); DAY = 86400


class Clock:
    def __init__(self, t=1_700_000_000.0): self.t = t
    def __call__(self): return self.t


def token_from(r): return r.cookie.split(";")[0].split("=", 1)[1]


class AdminTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = Store(str(Path(self.tmp.name) / "a.db")); self.clock = Clock()
        self.svc = AuthService(CFG, self.store, now=self.clock)
        self.owner_key = SoftAuthenticator(CFG.rp_id, CFG.origin)
        e = self.svc.enroll_owner(); r = self.svc.redeem(e.body["code"], "iPhone", "1.1.1.1")
        o = self.svc.register_options(r.body["ticket"], None)
        self.owner = token_from(self.svc.register_verify(o.body["challenge_id"], self.owner_key.register(o.body["options"]), r.body["ticket"], None, "iPhone", "iPhone"))
    def tearDown(self): self.store.close(); self.tmp.cleanup()

    def member(self, name="jill", sites=("notes",)):
        inv = self.svc.admin_invite(self.owner, name, list(sites), "30d", "member")
        got = self.svc.redeem(inv.body["code"], "iPhone", "2.2.2.2"); key = SoftAuthenticator(CFG.rp_id, CFG.origin)
        o = self.svc.register_options(got.body["ticket"], None)
        v = self.svc.register_verify(o.body["challenge_id"], key.register(o.body["options"]), got.body["ticket"], None, "iPhone", "iPhone")
        return key, token_from(v)

    def test_only_an_owner_on_a_passkey_session_may_administer(self):
        _, jill = self.member()
        for r in (self.svc.admin_guests(jill), self.svc.admin_invite(jill, "x", ["notes"], "1d", "guest"), self.svc.admin_revoke(jill, "bob"),
                  self.svc.admin_sites(jill, "bob", ["photos"], []), self.svc.admin_extend(jill, "bob", "7d")):
            self.assertEqual((r.status, r.body), (403, {"error": "owner only"}))
        self.assertEqual(self.svc.admin_guests(None).status, 403)

    def test_guests_listing(self):
        self.svc.admin_invite(self.owner, "bob", ["notes"], "2d", "guest")
        _, jill = self.member()
        g = self.svc.admin_guests(self.owner).body["guests"]
        self.assertEqual([x["name"] for x in g], ["bob", "jill"])
        bob, jl = g
        self.assertEqual((bob["role"], bob["passkeys"], bob["invites"][0]["active"], bob["invites"][0]["max_browsers"], bob["sessions"]), ("guest", 0, True, 3, []))
        self.assertEqual((jl["role"], jl["passkeys"], jl["invites"][0]["consumed"], len(jl["sessions"]), jl["sites"]), ("member", 1, True, 1, ["notes"]))
        self.assertEqual(jl["sessions"][0]["user_agent"], "iPhone")

    def test_grant_and_deny(self):
        _, jill = self.member()
        r = self.svc.admin_sites(self.owner, "jill", ["photos", "files"], ["notes"])
        self.assertEqual(r.body["sites"], ["files", "photos"])   # sites come back sorted, not in the order asked for
        self.assertEqual(self.svc.verify(jill, "photos.example.com", "GET", "/", "text/html").status, 200)
        self.assertEqual(self.svc.verify(jill, "notes.example.com", "GET", "/", "text/html").status, 302)
        self.assertEqual(self.svc.admin_sites(self.owner, "jill", ["elsewhere"], []).status, 400)
        self.assertEqual(self.svc.admin_sites(self.owner, "nobody", ["photos"], []).status, 404)
        self.assertEqual(self.svc.admin_sites(self.owner, "ada", ["photos"], []).status, 404)

    def test_revoke_member_keeps_keys_disables_login_and_grant_reenables(self):
        key, jill = self.member()
        r = self.svc.admin_revoke(self.owner, "jill")
        self.assertEqual(r.body, {"ok": True, "name": "jill", "keys_removed": False})
        self.assertEqual(self.svc.me(jill).status, 401)
        o = self.svc.login_options("2.2.2.2")
        self.assertEqual(self.svc.login_verify(o.body["challenge_id"], key.authenticate(o.body["options"]), "Mac", "2.2.2.2").status, 401)
        self.svc.admin_sites(self.owner, "jill", ["notes"], [])
        o2 = self.svc.login_options("2.2.2.2")
        self.assertEqual(self.svc.login_verify(o2.body["challenge_id"], key.authenticate(o2.body["options"]), "Mac", "2.2.2.2").status, 200)
        self.assertEqual(self.svc.admin_revoke(self.owner, "jill", keys=True).body["keys_removed"], True)
        o3 = self.svc.login_options("2.2.2.2")
        self.assertEqual(self.svc.login_verify(o3.body["challenge_id"], key.authenticate(o3.body["options"]), "Mac", "2.2.2.2").status, 401)

    def test_revoke_guest_kills_sessions_and_invites(self):
        inv = self.svc.admin_invite(self.owner, "bob", ["notes"], "2d", "guest")
        bob = token_from(self.svc.redeem(inv.body["code"], "x", "5.5.5.5"))
        self.assertEqual(self.svc.admin_revoke(self.owner, "bob").body["keys_removed"], True)
        self.assertEqual(self.svc.me(bob).status, 401)
        self.assertEqual(self.svc.redeem(inv.body["code"], "x", "5.5.5.5").status, 401)
        self.assertEqual(self.svc.admin_revoke(self.owner, "ada").status, 404)

    def test_passkeys_list_and_remove_keeps_at_least_one(self):
        keys = self.svc.passkeys_list(self.owner).body["passkeys"]
        self.assertEqual(len(keys), 1); self.assertEqual(keys[0]["label"], "iPhone")
        self.assertEqual(self.svc.passkeys_remove(self.owner, keys[0]["id"]).status, 400)
        o = self.svc.register_options(None, self.owner); second = SoftAuthenticator(CFG.rp_id, CFG.origin)
        self.svc.register_verify(o.body["challenge_id"], second.register(o.body["options"]), None, self.owner, "Mac", "mac")
        self.assertEqual(self.svc.passkeys_remove(self.owner, keys[0]["id"]).body, {"ok": True})
        self.assertEqual([k["label"] for k in self.svc.passkeys_list(self.owner).body["passkeys"]], ["mac"])
        inv = self.svc.admin_invite(self.owner, "bob", ["notes"], "2d", "guest")
        bob = token_from(self.svc.redeem(inv.body["code"], "x", "5.5.5.5"))
        self.assertEqual(self.svc.passkeys_list(bob).status, 403)

    def test_extend_keeps_a_guest_in_the_browser_he_already_has(self):
        """The point of extending rather than re-inviting: nothing is sent, and the browser he is
           already signed in on simply keeps working past the date it was going to stop."""
        inv = self.svc.admin_invite(self.owner, "bob", ["notes"], "2d", "guest")
        bob = token_from(self.svc.redeem(inv.body["code"], "phone", "5.5.5.5"))
        notes = lambda: self.svc.verify(bob, "notes.example.com", "GET", "/", "text/html").status
        self.assertEqual(notes(), 200)

        r = self.svc.admin_extend(self.owner, "bob", "10d")
        self.assertEqual(r.status, 200)
        self.assertEqual((r.body["name"], r.body["expires"]), ("bob", int(self.clock() + 10 * DAY)))
        self.assertEqual(r.body["moved"], 2)                    # his invite and his one session

        # Past the old deadline, where he would have been turned away.
        self.clock.t += 5 * DAY
        self.assertEqual(notes(), 200)
        # His browser was told a date when it was let in, so the cookie has to be revised or the
        # extension never reaches him. /_auth/me is the only thing that ever says so.
        self.assertIn(f"Max-Age={5 * DAY}", self.svc.me(bob).cookie)
        # The code still works for his other browsers, on the new deadline.
        self.assertEqual(self.svc.redeem(inv.body["code"], "laptop", "5.5.5.5").status, 200)

        self.clock.t += 6 * DAY
        self.assertEqual(notes(), 302)
        self.assertEqual(self.svc.me(bob).status, 401)

    def test_extend_only_ever_moves_a_deadline_forward(self):
        self.svc.admin_invite(self.owner, "bob", ["notes"], "30d", "guest")
        r = self.svc.admin_extend(self.owner, "bob", "2d")
        # Asking for less than he has does not take his time away; he keeps the later date and
        # nothing moved, which is what the caller is told.
        self.assertEqual((r.body["moved"], r.body["expires"]), (0, int(self.clock() + 30 * DAY)))

    def test_extend_refuses_what_it_cannot_sensibly_do(self):
        self.assertEqual(self.svc.admin_extend(self.owner, "nobody", "7d").status, 404)
        self.assertEqual(self.svc.admin_extend(self.owner, "ada", "7d").status, 404)          # the owner has no deadline

        self.svc.admin_invite(self.owner, "bob", ["notes"], "2d", "guest")
        self.assertEqual(self.svc.admin_extend(self.owner, "bob", "not-a-ttl").status, 400)

        # Revoked: extending must not be a quiet way back in. Compare with admin_sites, which does
        # re-enable, because granting a site is a deliberate act of letting someone back.
        self.svc.admin_revoke(self.owner, "bob")
        r = self.svc.admin_extend(self.owner, "bob", "7d")
        self.assertEqual(r.status, 400); self.assertIn("revoked", r.body["error"])
        self.assertTrue(self.store.user_by_name("bob").disabled)

        # Expired, not revoked: there is nothing running, so there is nothing to extend.
        self.svc.admin_invite(self.owner, "ana", ["notes"], "2d", "guest")
        self.clock.t += 3 * DAY
        r2 = self.svc.admin_extend(self.owner, "ana", "7d")
        self.assertEqual(r2.status, 400); self.assertIn("nothing running", r2.body["error"])

    def test_extend_a_member_moves_her_session_without_touching_her_key(self):
        _, jill = self.member()
        r = self.svc.admin_extend(self.owner, "jill", "90d")
        self.assertEqual((r.status, r.body["expires"]), (200, int(self.clock() + 90 * DAY)))
        self.clock.t += 60 * DAY                                # past the 30 days she started with
        self.assertEqual(self.svc.me(jill).status, 200)
        self.assertEqual(len(self.svc.passkeys_list(jill).body["passkeys"]), 1)
