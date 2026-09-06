import contextlib, io, tempfile, threading, unittest
from pathlib import Path
from doorman import passkeys
from doorman.config import Config
from doorman.service import OPTIONS_LIMIT, RATE_LIMIT, RATE_WINDOW, AuthService, Result
from doorman.store import Store
from tests.softauth import SoftAuthenticator

CFG = Config.from_env({})
DAY = 86400


class Clock:
    def __init__(self, t=1_700_000_000.0): self.t = t
    def __call__(self): return self.t


def token_from(result): return result.cookie.split(";")[0].split("=", 1)[1]


class LoginTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = Store(str(Path(self.tmp.name) / "a.db")); self.clock = Clock()
        self.svc = AuthService(CFG, self.store, now=self.clock)
    def tearDown(self): self.store.close(); self.tmp.cleanup()

    def enroll_owner(self):
        """The CLI path: enroll-owner -> redeem the code -> make a passkey -> logged in."""
        auth = SoftAuthenticator(CFG.rp_id, CFG.origin)
        e = self.svc.enroll_owner()
        self.assertEqual(e.body["name"], "ada"); self.assertIn("#i=" + e.body["code"], e.body["link"])
        r = self.svc.redeem(e.body["code"], "iPhone", "1.2.3.4")
        self.assertEqual((r.status, r.body["kind"], r.body["name"]), (200, "owner", "ada"))
        o = self.svc.register_options(r.body["ticket"], None)
        self.assertEqual(o.status, 200)
        v = self.svc.register_verify(o.body["challenge_id"], auth.register(o.body["options"]), r.body["ticket"], None, "iPhone", "iphone")
        self.assertEqual(v.status, 200); self.assertIsNotNone(v.cookie); self.assertEqual(v.body["role"], "owner")
        return auth, v

    def test_owner_enrollment_then_passkey_login(self):
        auth, first = self.enroll_owner()
        self.assertEqual(self.svc.me(token_from(first)).body["name"], "ada")
        o = self.svc.login_options("1.2.3.4")
        self.assertEqual(o.status, 200); self.assertEqual(o.body["options"]["rpId"], "example.com")
        v = self.svc.login_verify(o.body["challenge_id"], auth.authenticate(o.body["options"]), "Mac", "1.2.3.4")
        self.assertEqual(v.status, 200); self.assertIn("Max-Age=" + str(30 * DAY), v.cookie)
        self.assertEqual(self.svc.verify(token_from(v), "archive.example.com", "GET", "/", "text/html").status, 200)
        self.assertEqual(self.store.credentials_for(self.store.user_by_name("ada").id)[0].label, "iphone")

    def test_enrollment_code_is_single_use_and_the_owner_can_add_a_second_key(self):
        auth, first = self.enroll_owner()
        e2 = self.svc.enroll_owner()                               # recovery: a second enrollment attaches to the same owner
        self.assertEqual(self.store.user_by_name("ada").role, "owner"); self.assertEqual(len(self.store.all_users()), 1)
        used_code = e2.body["code"]
        r = self.svc.redeem(used_code, "iPad", "1.2.3.4"); self.assertEqual(r.status, 200)
        o = self.svc.register_options(r.body["ticket"], None); auth2 = SoftAuthenticator(CFG.rp_id, CFG.origin)
        self.assertEqual(self.svc.register_verify(o.body["challenge_id"], auth2.register(o.body["options"]), r.body["ticket"], None, "iPad").status, 200)
        self.assertEqual(self.svc.redeem(used_code, "iPad", "1.2.3.4").status, 401)   # consumed
        # passkey add from a logged-in passkey session
        tok = token_from(first)
        o3 = self.svc.register_options(None, tok); auth3 = SoftAuthenticator(CFG.rp_id, CFG.origin)
        self.assertEqual(len(o3.body["options"]["excludeCredentials"]), 2)
        v3 = self.svc.register_verify(o3.body["challenge_id"], auth3.register(o3.body["options"]), None, tok, "Mac")
        self.assertEqual((v3.status, v3.body), (200, {"ok": True, "passkeys": 3}))

    def test_login_failures_are_rate_limited_and_unknown_keys_refused(self):
        auth, _ = self.enroll_owner()
        stranger = SoftAuthenticator(CFG.rp_id, CFG.origin)
        for i in range(RATE_LIMIT):
            o = self.svc.login_options("9.9.9.9")
            self.assertEqual(self.svc.login_verify(o.body["challenge_id"], stranger.authenticate(o.body["options"]), "x", "9.9.9.9").status, 401)
        o = self.svc.login_options("9.9.9.9")
        self.assertEqual(self.svc.login_verify(o.body["challenge_id"], auth.authenticate(o.body["options"]), "x", "9.9.9.9").status, 429)
        o2 = self.svc.login_options("8.8.8.8")
        self.assertEqual(self.svc.login_verify(o2.body["challenge_id"], auth.authenticate(o2.body["options"]), "x", "8.8.8.8").status, 200)
        self.clock.t += 301
        o3 = self.svc.login_options("9.9.9.9")
        self.assertEqual(self.svc.login_verify(o3.body["challenge_id"], auth.authenticate(o3.body["options"]), "x", "9.9.9.9").status, 200)

    def test_login_options_is_capped_per_caller(self):
        """The route needs no session, takes no body, and writes a challenge row every time. Its
        ceiling is far above anything a person opening the login page could reach, and well below
        what it takes to fill a disk or to sit on the store's single lock all day."""
        for _ in range(OPTIONS_LIMIT):
            self.assertEqual(self.svc.login_options("7.7.7.7").status, 200)
        self.assertEqual(self.svc.login_options("7.7.7.7").status, 429)
        self.assertEqual(self.svc.login_options("7.7.7.8").status, 200)      # another caller is unaffected
        self.clock.t += RATE_WINDOW + 1
        self.assertEqual(self.svc.login_options("7.7.7.7").status, 200)      # and the window ends

    def test_a_challenge_cannot_be_replayed_and_expires(self):
        auth, _ = self.enroll_owner()
        o = self.svc.login_options("1.1.1.1"); cred = auth.authenticate(o.body["options"])
        self.assertEqual(self.svc.login_verify(o.body["challenge_id"], cred, "x", "1.1.1.1").status, 200)
        self.assertEqual(self.svc.login_verify(o.body["challenge_id"], cred, "x", "1.1.1.1").status, 401)
        o2 = self.svc.login_options("1.1.1.1"); self.clock.t += 301
        self.assertEqual(self.svc.login_verify(o2.body["challenge_id"], auth.authenticate(o2.body["options"]), "x", "1.1.1.1").status, 401)

    def test_a_stale_sign_counter_is_logged_and_never_lowers_the_stored_count(self):
        """The clone signal is only worth computing if someone can act on it, so it is logged with the
        name and the two counts. And the regressed value must not be written back: storing it would
        make the next assertion look like an advance, so the one credential there is reason to watch
        would be the one that never warns again."""
        auth, _ = self.enroll_owner()
        cred = self.store.credentials_for(self.store.user_by_name("ada").id)[0]
        self.store.touch_credential(cred.id, 7, self.clock())        # as if an earlier assertion had counted 7
        o = self.svc.login_options("1.1.1.1")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            v = self.svc.login_verify(o.body["challenge_id"], auth.authenticate(o.body["options"]), "Mac", "1.1.1.1")
        self.assertEqual(v.status, 200)                              # synced passkeys keep no counter: noted, not fatal
        self.assertIn("ada", out.getvalue()); self.assertIn("counter", out.getvalue())
        self.assertEqual(self.store.credential_by_id(auth.cred_id).sign_count, 7)     # kept, not lowered to 1

    def test_disabled_user_cannot_log_in_with_a_valid_key(self):
        auth, _ = self.enroll_owner()
        self.store.set_disabled(self.store.user_by_name("ada").id, True)
        o = self.svc.login_options("1.1.1.1")
        self.assertEqual(self.svc.login_verify(o.body["challenge_id"], auth.authenticate(o.body["options"]), "x", "1.1.1.1").status, 401)

    def test_two_tickets_from_one_code_yield_only_one_passkey(self):
        """A leaked owner enrollment code, redeemed twice before either result is used, must not mint two
        passkeys: only the newer ticket stays live, so completing with it is the one registration that can
        succeed and the owner ends up with exactly one credential."""
        e = self.svc.enroll_owner()
        r1 = self.svc.redeem(e.body["code"], "iPhone", "1.2.3.4")
        r2 = self.svc.redeem(e.body["code"], "iPad", "1.2.3.4")
        self.assertEqual((r1.status, r2.status), (200, 200))
        winner = SoftAuthenticator(CFG.rp_id, CFG.origin)
        o = self.svc.register_options(r2.body["ticket"], None)
        self.assertEqual(o.status, 200)
        v = self.svc.register_verify(o.body["challenge_id"], winner.register(o.body["options"]), r2.body["ticket"], None, "iPad")
        self.assertEqual(v.status, 200); self.assertIsNotNone(v.cookie); self.assertEqual(v.body["role"], "owner")
        self.assertEqual(self.svc.register_options(r1.body["ticket"], None).status, 401)   # r1's ticket died when r2 was issued
        self.assertEqual(len(self.store.credentials_for(self.store.user_by_name("ada").id)), 1)

    def test_a_ticket_dies_when_a_newer_one_is_issued_for_the_same_invite(self):
        """Same mechanism, exercised on a recovery code for an owner who already has a passkey: ticket A goes
        stale the instant ticket B is issued for the same invite, regardless of which one anyone tries first."""
        auth, first = self.enroll_owner()
        e2 = self.svc.enroll_owner()                                  # a leaked recovery code
        code = e2.body["code"]
        a = self.svc.redeem(code, "iPad", "1.2.3.4")                  # ticket A
        b = self.svc.redeem(code, "iPad-2", "1.2.3.4")                # ticket B, issued after A
        self.assertEqual((a.status, b.status), (200, 200))
        self.assertEqual(self.svc.register_options(a.body["ticket"], None).status, 401)   # A refused
        device_b = SoftAuthenticator(CFG.rp_id, CFG.origin)
        o = self.svc.register_options(b.body["ticket"], None)
        self.assertEqual(o.status, 200)
        v = self.svc.register_verify(o.body["challenge_id"], device_b.register(o.body["options"]), b.body["ticket"], None, "iPad-2")
        self.assertEqual(v.status, 200)                                                   # B succeeds
        self.assertEqual(len(self.store.credentials_for(self.store.user_by_name("ada").id)), 2)

    def test_consuming_an_invite_twice_is_a_win_then_a_loss_at_the_store_level(self):
        """The backstop the enrollment race relies on: consuming an invite is an atomic check-and-set,
        not a check followed by a write, so exactly one caller can ever win it, and the recorded
        consumption is the winner's, unaffected by whoever calls in after."""
        user = self.store.create_user("bob", "member", ["notes.example.com"], 1.0)
        inv = self.store.create_invite("a-b-c-01", user.id, "member", 1000.0, 1.0)
        self.assertTrue(self.store.consume_invite(inv.id, 10.0))
        self.assertFalse(self.store.consume_invite(inv.id, 20.0))
        self.assertEqual(self.store.invite_by_id(inv.id).consumed_at, 10.0)

    def test_the_loser_of_a_same_ticket_enrollment_race_is_refused(self):
        """Two registration ceremonies started from the same still-live enroll ticket: whichever
        request's consumption loses the race must be refused, not silently minting a second passkey
        for one enrollment code."""
        e = self.svc.enroll_owner()
        r = self.svc.redeem(e.body["code"], "iPhone", "1.2.3.4")
        ticket = r.body["ticket"]
        o1 = self.svc.register_options(ticket, None)
        o2 = self.svc.register_options(ticket, None)
        dev1, dev2 = SoftAuthenticator(CFG.rp_id, CFG.origin), SoftAuthenticator(CFG.rp_id, CFG.origin)
        cred1, cred2 = dev1.register(o1.body["options"]), dev2.register(o2.body["options"])
        v1 = self.svc.register_verify(o1.body["challenge_id"], cred1, ticket, None, "iPhone")
        self.assertEqual(v1.status, 200)
        v2 = self.svc.register_verify(o2.body["challenge_id"], cred2, ticket, None, "iPhone-2")
        self.assertEqual(v2.status, 401)
        self.assertEqual(len(self.store.credentials_for(self.store.user_by_name("ada").id)), 1)

    def test_two_racing_enrollments_on_one_ticket_yield_exactly_one_passkey(self):
        """The interleaving itself, forced with a barrier rather than timing: two requests holding the
        same live enroll ticket both get past _enrolling_user's peek and both finish verifying their
        WebAuthn registration before either one claims the invite. Only one may come away with a
        credential, and the refused one must leave nothing usable behind -- in particular its device
        must not be able to log in afterwards."""
        e = self.svc.enroll_owner()
        r = self.svc.redeem(e.body["code"], "iPhone", "1.2.3.4")
        ticket = r.body["ticket"]
        o1, o2 = self.svc.register_options(ticket, None), self.svc.register_options(ticket, None)
        self.assertEqual((o1.status, o2.status), (200, 200))
        dev1, dev2 = SoftAuthenticator(CFG.rp_id, CFG.origin), SoftAuthenticator(CFG.rp_id, CFG.origin)
        cred1, cred2 = dev1.register(o1.body["options"]), dev2.register(o2.body["options"])

        # The seam: hold both calls inside register_verify at the moment the WebAuthn check has passed
        # and nothing durable has been written yet, then release them together. No sleeps, no clock.
        gate = threading.Barrier(2, timeout=10)
        real_verify = passkeys.verify_registration

        def paused_verify(*args, **kwargs):
            out = real_verify(*args, **kwargs)
            gate.wait()
            return out

        passkeys.verify_registration = paused_verify
        self.addCleanup(setattr, passkeys, "verify_registration", real_verify)
        self.addCleanup(gate.abort)

        out = {}

        def enroll(name, options, credential, label):
            try:
                out[name] = self.svc.register_verify(options.body["challenge_id"], credential, ticket, None, label, label)
            except BaseException as exc:            # a broken barrier must fail the test, not hang it
                out[name] = exc

        threads = [threading.Thread(target=enroll, args=("one", o1, cred1, "iPhone")),
                   threading.Thread(target=enroll, args=("two", o2, cred2, "iPad"))]
        for t in threads: t.start()
        for t in threads: t.join(20)
        self.assertFalse(any(t.is_alive() for t in threads), "register_verify never returned")
        self.assertEqual(sorted(out), ["one", "two"])
        for name, res in out.items():
            self.assertIsInstance(res, Result, f"thread {name} raised {res!r}")

        won = [x for x in out.values() if x.status == 200]
        lost = [x for x in out.values() if x.status != 200]
        self.assertEqual((len(won), len(lost)), (1, 1))
        self.assertIsNotNone(won[0].cookie); self.assertEqual(won[0].body["role"], "owner")
        self.assertEqual((lost[0].status, lost[0].body, lost[0].cookie), (401, {"error": "permission denied"}, None))

        winner, loser = (dev1, dev2) if out["one"].status == 200 else (dev2, dev1)
        creds = self.store.credentials_for(self.store.user_by_name("ada").id)
        self.assertEqual([c.credential_id for c in creds], [winner.cred_id])   # exactly one, and it is the winner's

        # what actually matters: the refused request's key is not a working passkey
        o = self.svc.login_options("5.5.5.5")
        refused = self.svc.login_verify(o.body["challenge_id"], loser.authenticate(o.body["options"]), "x", "5.5.5.5")
        self.assertEqual(refused.status, 401); self.assertIsNone(refused.cookie)
        o = self.svc.login_options("5.5.5.5")
        allowed = self.svc.login_verify(o.body["challenge_id"], winner.authenticate(o.body["options"]), "x", "5.5.5.5")
        self.assertEqual(allowed.status, 200)
        self.assertEqual(self.svc.me(token_from(allowed)).body["name"], "ada")
        self.assertEqual(self.svc.register_options(ticket, None).status, 401)  # the loser cannot retry the ticket
