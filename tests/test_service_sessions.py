import tempfile, unittest
from pathlib import Path
from doorman.config import Config
from doorman.service import AuthService, parse_ttl
from doorman.store import Store

CFG = Config.from_env({})
DAY = 86400


class Clock:
    def __init__(self, t=1_700_000_000.0): self.t = t
    def __call__(self): return self.t


class ServiceSessionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = Store(str(Path(self.tmp.name) / "a.db")); self.clock = Clock()
        self.svc = AuthService(CFG, self.store, now=self.clock)
        self.owner = self.store.create_user("ada", "owner", ["*"], self.clock())
        self.jill = self.store.create_user("jill", "member", ["notes.example.com", "photos.example.com"], self.clock())
    def tearDown(self): self.store.close(); self.tmp.cleanup()
    def token_from(self, result): return result.cookie.split(";")[0].split("=", 1)[1]

    def test_cookie_shape(self):
        c = self.svc.cookie("abc", 60)
        self.assertEqual(c, "doorman_session=abc; Domain=.example.com; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Lax")
        self.assertIn("Max-Age=0", self.svc.clear_cookie())

    def test_verify_without_session_redirects_page_loads_and_401s_fetches(self):
        r = self.svc.verify(None, "notes.example.com", "GET", "/recipes?x=1", "text/html,*/*")
        self.assertEqual(r.status, 302)
        self.assertEqual(r.redirect, "https://example.com/login.html?next=https%3A%2F%2Fnotes.example.com%2Frecipes%3Fx%3D1")
        r2 = self.svc.verify(None, "notes.example.com", "GET", "/data.json", "application/json")
        self.assertEqual((r2.status, r2.body), (401, {"error": "login required"}))
        r3 = self.svc.verify(None, "notes.example.com", "POST", "/api", "text/html")
        self.assertEqual(r3.status, 401)

    def test_verify_allows_and_forbids_by_host(self):
        started = self.svc._start_session(self.jill, None, self.clock() + 30 * DAY, "UA")
        tok = self.token_from(started)
        ok = self.svc.verify(tok, "notes.example.com", "GET", "/", "text/html")
        self.assertEqual((ok.status, ok.headers), (200, {"X-Doorman-User": "jill", "X-Doorman-Role": "member"}))
        self.assertEqual(self.svc.verify(tok, "example.com", "GET", "/", "text/html").status, 200)
        no = self.svc.verify(tok, "archive.example.com", "GET", "/", "text/html")
        self.assertEqual((no.status, no.redirect), (302, "https://example.com/denied.html?host=archive.example.com"))
        self.assertEqual(self.svc.verify(tok, "archive.example.com", "GET", "/x.json", "application/json").status, 403)

    def test_me_reports_identity_and_renews_only_passkey_sessions_near_expiry(self):
        tok = self.token_from(self.svc._start_session(self.jill, None, self.clock() + 30 * DAY, "UA"))
        me = self.svc.me(tok)
        # The cookie always comes back, but a call that is not renewing must not change anything:
        # same token, and a life matching the row rather than a fresh 30 days.
        self.assertEqual(me.status, 200)
        self.assertEqual(self.token_from(me), tok); self.assertIn(f"Max-Age={30 * DAY}", me.cookie)
        self.assertEqual(me.body["name"], "jill"); self.assertEqual(me.body["role"], "member")
        self.assertEqual(me.body["sites"], ["notes", "photos"]); self.assertEqual(me.body["hosts"], ["notes.example.com", "photos.example.com"])
        self.clock.t += 20 * DAY
        me2 = self.svc.me(tok)
        self.assertIsNotNone(me2.cookie); self.assertIn(f"Max-Age={30 * DAY}", me2.cookie); self.assertEqual(me2.body["expires"], int(self.clock() + 30 * DAY))
        # a guest session is never renewed
        bob = self.store.create_user("bob", "guest", ["notes.example.com"], self.clock())
        inv = self.store.create_invite("a-b-c-00", bob.id, "guest", self.clock() + 2 * DAY, self.clock())
        gtok = self.token_from(self.svc._start_session(bob, inv.id, inv.expires_at, "UA"))
        gme = self.svc.me(gtok)
        # He gets a cookie too, but it says what his invite already said: two days, not thirty.
        self.assertIn(f"Max-Age={2 * DAY}", gme.cookie); self.assertEqual(gme.body["expires"], int(inv.expires_at))
        # owner sees the wildcard
        otok = self.token_from(self.svc._start_session(self.owner, None, self.clock() + 30 * DAY, "UA"))
        self.assertEqual(self.svc.me(otok).body["sites"], ["*"])

    def test_expired_and_logged_out_sessions_are_gone(self):
        tok = self.token_from(self.svc._start_session(self.jill, None, self.clock() + 30 * DAY, "UA"))
        self.assertEqual(self.svc.logout(tok).cookie, self.svc.clear_cookie())
        self.assertEqual(self.svc.me(tok).status, 401)
        tok2 = self.token_from(self.svc._start_session(self.jill, None, self.clock() + 30 * DAY, "UA"))
        self.clock.t += 31 * DAY
        self.assertEqual(self.svc.me(tok2).status, 401)

    def test_parse_ttl(self):
        self.assertEqual(parse_ttl(None), 7 * DAY); self.assertEqual(parse_ttl("3d"), 3 * DAY); self.assertEqual(parse_ttl(" 12H "), 12 * 3600)
        for bad in ("0d", "400d", "3w", "soon"):
            with self.assertRaises(ValueError): parse_ttl(bad)
