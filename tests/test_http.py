import contextlib, http.client, io, json, sqlite3, tempfile, threading, unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from doorman.config import Config
from doorman.http import MAX_BODY, make_handler, sweep
from doorman.service import RATE_LIMIT, AuthService
from doorman.store import Store
from tests.softauth import SoftAuthenticator

CFG = Config.from_env({})


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); cls.store = Store(str(Path(cls.tmp.name) / "a.db"))
        cls.svc = AuthService(CFG, cls.store)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.svc)); cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close(); cls.store.close(); cls.tmp.cleanup()

    def call(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Content-Type": "application/json"}; h.update(headers or {})
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse(); data = r.read(); c.close()
        try: parsed = json.loads(data) if data else None
        except ValueError: parsed = None
        return r.status, dict(r.getheaders()), parsed

    def post(self, path, body=None, cookie=None):
        h = {"Origin": CFG.origin, "X-Doorman-Request": "1", "X-Forwarded-For": "10.0.0.1"}
        if cookie: h["Cookie"] = cookie
        return self.call("POST", path, body or {}, h)

    def test_health(self):
        self.assertEqual(self.call("GET", "/_auth/health")[0], 200)

    def test_verify_redirects_page_loads_and_401s_the_rest(self):
        s, h, _ = self.call("GET", "/_auth/verify", headers={"X-Forwarded-Host": "notes.example.com", "X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/a?b=1", "Accept": "text/html"})
        self.assertEqual(s, 302); self.assertEqual(h["Location"], "https://example.com/login.html?next=https%3A%2F%2Fnotes.example.com%2Fa%3Fb%3D1")
        self.assertEqual(h.get("Cache-Control"), "no-store")
        s2, _, b2 = self.call("GET", "/_auth/verify", headers={"X-Forwarded-Host": "notes.example.com", "Accept": "application/json"})
        self.assertEqual((s2, b2), (401, {"error": "login required"}))

    def test_verify_does_not_let_an_unknown_host_header_pick_its_own_redirect(self):
        s, h, _ = self.call("GET", "/_auth/verify", headers={"X-Forwarded-Host": "evil.example", "X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/steal-me", "Accept": "text/html"})
        self.assertEqual(s, 302)
        self.assertEqual(h["Location"], "https://example.com/login.html?next=https%3A%2F%2Fexample.com%2F")
        self.assertNotIn("evil.example", h["Location"])

    def test_posts_need_origin_and_the_custom_header(self):
        self.assertEqual(self.call("POST", "/_auth/login/options", {})[0], 403)
        self.assertEqual(self.call("POST", "/_auth/login/options", {}, {"Origin": CFG.origin})[0], 403)
        self.assertEqual(self.call("POST", "/_auth/login/options", {}, {"Origin": "https://evil.example", "X-Doorman-Request": "1"})[0], 403)
        self.assertEqual(self.post("/_auth/login/options")[0], 200)

    def test_bad_json_and_unknown_paths(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port); c.request("POST", "/_auth/invite/redeem", body=b"{not json", headers={"Origin": CFG.origin, "X-Doorman-Request": "1", "Content-Type": "application/json"})
        self.assertEqual(c.getresponse().status, 400); c.close()
        self.assertEqual(self.post("/_auth/invite/redeem", [1, 2])[0], 400)
        self.assertEqual(self.call("GET", "/_auth/nope")[0], 404); self.assertEqual(self.post("/_auth/nope")[0], 404)

    def raw_post(self, path, content_length, send_bytes=b""):
        """POST with an explicit (possibly malformed) Content-Length header, bypassing http.client's own bookkeeping."""
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            c.putrequest("POST", path)
            c.putheader("Origin", CFG.origin)
            c.putheader("X-Doorman-Request", "1")
            c.putheader("Content-Type", "application/json")
            c.putheader("Content-Length", content_length)
            c.endheaders()
            if send_bytes:
                c.send(send_bytes)
            r = c.getresponse(); data = r.read()
            try: parsed = json.loads(data) if data else None
            except ValueError: parsed = None
            return r.status, parsed
        finally:
            c.close()

    def test_oversized_body_is_refused_as_bad_json(self):
        s, _, b = self.post("/_auth/invite/redeem", {"code": "a" * (MAX_BODY)})
        self.assertEqual((s, b), (400, {"error": "bad json"}))

    def test_malformed_content_length_is_refused_as_bad_json(self):
        s, b = self.raw_post("/_auth/invite/redeem", "abc")
        self.assertEqual((s, b), (400, {"error": "bad json"}))

    def test_negative_content_length_is_refused_as_bad_json(self):
        # Also proves the fix doesn't fall back to "read until the socket closes": the response
        # comes back well within the client's 5s timeout, holding no thread hostage.
        s, b = self.raw_post("/_auth/invite/redeem", "-1")
        self.assertEqual((s, b), (400, {"error": "bad json"}))

    def test_full_flow_over_http_sets_a_proper_cookie(self):
        e = self.svc.enroll_owner()
        s, h, b = self.post("/_auth/invite/redeem", {"code": e.body["code"]})
        self.assertEqual((s, b["kind"]), (200, "owner"))
        s, _, o = self.post("/_auth/register/options", {"ticket": b["ticket"]}); self.assertEqual(s, 200)
        key = SoftAuthenticator(CFG.rp_id, CFG.origin)
        s, h, v = self.post("/_auth/register/verify", {"challenge_id": o["challenge_id"], "ticket": b["ticket"], "credential": key.register(o["options"]), "label": "test"})
        self.assertEqual(s, 200); cookie = h["Set-Cookie"]
        self.assertTrue(cookie.startswith("doorman_session=")); self.assertIn("Domain=.example.com", cookie); self.assertIn("HttpOnly", cookie); self.assertIn("Secure", cookie); self.assertIn("SameSite=Lax", cookie)
        raw = cookie.split(";")[0]
        s, h, me = self.call("GET", "/_auth/me", headers={"Cookie": raw}); self.assertEqual((s, me["name"], me["role"]), (200, "ada", "owner"))
        s, h, _ = self.call("GET", "/_auth/verify", headers={"Cookie": raw, "X-Forwarded-Host": "archive.example.com", "Accept": "text/html"})
        self.assertEqual((s, h["X-Doorman-User"], h["X-Doorman-Role"]), (200, "ada", "owner"))
        s, _, inv = self.post("/_auth/admin/invite", {"name": "bob", "sites": ["notes"], "ttl": "1d", "kind": "guest"}, cookie=raw); self.assertEqual(s, 200)
        s, _, g = self.call("GET", "/_auth/admin/guests", headers={"Cookie": raw}); self.assertIn("bob", [x["name"] for x in g["guests"]])
        s, h, _ = self.post("/_auth/logout", cookie=raw); self.assertIn("Max-Age=0", h["Set-Cookie"])
        self.assertEqual(self.call("GET", "/_auth/me", headers={"Cookie": raw})[0], 401)
        # passkey login over the wire
        s, _, lo = self.post("/_auth/login/options"); s, h, _ = self.post("/_auth/login/verify", {"challenge_id": lo["challenge_id"], "credential": key.authenticate(lo["options"])})
        self.assertEqual(s, 200); self.assertIn("doorman_session=", h["Set-Cookie"])

    def test_revoke_does_not_treat_the_string_false_as_true(self):
        e = self.svc.enroll_owner()
        s, h, b = self.post("/_auth/invite/redeem", {"code": e.body["code"]})
        s, _, o = self.post("/_auth/register/options", {"ticket": b["ticket"]})
        key = SoftAuthenticator(CFG.rp_id, CFG.origin)
        s, h, v = self.post("/_auth/register/verify", {"challenge_id": o["challenge_id"], "ticket": b["ticket"], "credential": key.register(o["options"]), "label": "owner key"})
        raw = h["Set-Cookie"].split(";")[0]
        s, _, inv = self.post("/_auth/admin/invite", {"name": "alice", "sites": ["notes"], "ttl": "1d", "kind": "member"}, cookie=raw)
        self.assertEqual(s, 200)
        s, _, red = self.post("/_auth/invite/redeem", {"code": inv["code"]})
        s, _, o2 = self.post("/_auth/register/options", {"ticket": red["ticket"]})
        alice_key = SoftAuthenticator(CFG.rp_id, CFG.origin)
        self.post("/_auth/register/verify", {"challenge_id": o2["challenge_id"], "ticket": red["ticket"], "credential": alice_key.register(o2["options"]), "label": "alice key"})
        alice_id = self.svc.store.user_by_name("alice").id
        self.assertEqual(len(self.svc.store.credentials_for(alice_id)), 1)
        s, _, out = self.post("/_auth/admin/revoke", {"name": "alice", "keys": "false"}, cookie=raw)
        self.assertEqual((s, out["ok"], out["keys_removed"]), (200, True, False))
        self.assertEqual(len(self.svc.store.credentials_for(alice_id)), 1)

    def test_rate_limit_keys_off_the_last_forwarded_for_hop_not_the_first(self):
        # The peer here is always loopback (127.0.0.1), same as behind Caddy in production, so the
        # X-Forwarded-For branch always runs. Caddy is configured with no trusted_proxies, so it
        # discards whatever the client sent and writes only its own value: in production this header
        # is one hop, not a chain. Reading the *last* entry is what holds either way -- it is Caddy's
        # own value today, and it stays Caddy's own value if trusted_proxies is ever configured and
        # Caddy starts appending after the client's. A client rotating leading entries of its own
        # invention, as this test does, must never be able to move the bucket it lands in.
        trusted_hop = "203.0.113.9"
        for i in range(RATE_LIMIT):
            headers = {"Origin": CFG.origin, "X-Doorman-Request": "1", "X-Forwarded-For": f"198.51.100.{i}, {trusted_hop}"}
            s, _, _ = self.call("POST", "/_auth/invite/redeem", {"code": "not-a-real-code"}, headers)
            self.assertEqual(s, 401)
        headers = {"Origin": CFG.origin, "X-Doorman-Request": "1", "X-Forwarded-For": f"198.51.100.250, {trusted_hop}"}
        s, _, b = self.call("POST", "/_auth/invite/redeem", {"code": "not-a-real-code"}, headers)
        self.assertEqual((s, b), (429, {"error": "too many tries. wait a bit."}))


class SweepTest(unittest.TestCase):
    """Housekeeping. Rows are otherwise only removed when someone completes the ceremony they belong
    to, and /_auth/login/options needs no session and writes one on every call -- so without a sweep
    an abandoned ceremony's row lives forever and a stranger can grow the database without bound."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = Store(str(Path(self.tmp.name) / "s.db"))

    def tearDown(self):
        self.store.close(); self.tmp.cleanup()

    def test_a_sweep_reclaims_expired_challenges_and_leaves_live_ones(self):
        dead = self.store.create_challenge("login", b"old", 100.0)
        live = self.store.create_challenge("login", b"new", 900.0)
        self.store.note_failure("k", 100.0, 300)
        sweep(self.store, 500.0)
        self.assertIsNone(self.store.peek_challenge(dead, "login", 50.0))     # gone, not merely expired
        self.assertIsNotNone(self.store.peek_challenge(live, "login", 500.0))
        self.assertEqual(self.store.failures("k", 100.0, 300), 1)             # still inside its retention
        sweep(self.store, 100.0 + 3601)
        self.assertEqual(self.store.failures("k", 100.0, 300), 0)

    def test_a_sweep_that_raises_is_logged_and_survived(self):
        """The sweeper is a daemon thread inside the service: a locked database on one pass must
        cost that pass and nothing else."""
        class Broken:
            def purge(self, now):
                raise sqlite3.OperationalError("database is locked")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            sweep(Broken(), 1.0)
        self.assertIn("purge", out.getvalue())
