import tempfile, unittest
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from doorman.config import Config
from doorman.service import RATE_LIMIT, AuthService
from doorman.store import Store
from tests.softauth import SoftAuthenticator

CFG = Config.from_env({}); DAY = 86400

# What the login page will accept as a `next` value, transcribed one refusal at a time from `dest()`
# in example-portal/site/assets/js/login.js. Anything it refuses falls back to "./" — the site
# root — which is exactly the bug this destination exists to fix, so a link that trips any of these
# is silently no better than no link at all.
#
# These are the page's rules restated, not a Python port of `dest()`. A port would agree with our own
# misreading of the page and prove nothing; each line here can be held up against the page and
# checked by eye. Every entry is (what the page requires, a predicate over the decoded `next`).
LOGIN_PAGE_NEXT_RULES = (
    ('present at all — `if (!next ...) return "./"`',
     lambda n: bool(n)),
    ('no backslash anywhere in it — `/\\\\/.test(next)`',
     lambda n: "\\" not in n),
    ('not protocol-relative — `/^\\/\\//.test(next)`',
     lambda n: not n.startswith("//")),
    ('parses as a URL with a scheme and a host — `new URL(next, location.href)`',
     lambda n: bool(urlsplit(n).scheme and urlsplit(n).hostname)),
    ('no credentials in it — `if (u.username || u.password) return "./"`',
     lambda n: not urlsplit(n).username and not urlsplit(n).password),
    ('its path is not the login page itself — `if (/login\\.html$/.test(u.pathname)) return "./"`',
     lambda n: not urlsplit(n).path.endswith("login.html")),
    ('https, on example.com or a subdomain of it — the only cross-host branch that returns u.href',
     lambda n: urlsplit(n).scheme == "https" and (urlsplit(n).hostname == "example.com"
                                                  or urlsplit(n).hostname.endswith(".example.com"))),
)


class Clock:
    def __init__(self, t=1_700_000_000.0): self.t = t
    def __call__(self): return self.t


def token_from(r): return r.cookie.split(";")[0].split("=", 1)[1]


class InviteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = Store(str(Path(self.tmp.name) / "a.db")); self.clock = Clock()
        self.svc = AuthService(CFG, self.store, now=self.clock)
    def tearDown(self): self.store.close(); self.tmp.cleanup()

    def test_guest_invite_three_browsers_then_full_and_ends_with_the_invite(self):
        r = self.svc.create_invite("bob", ["notes", "photos"], "3d", "guest")
        self.assertEqual(r.status, 200); self.assertEqual(r.body["sites"], ["notes", "photos"]); self.assertEqual(r.body["expires"], int(self.clock() + 3 * DAY))
        self.assertRegex(r.body["code"], r"^[a-z]+-[a-z]+-[a-z]+-\d\d$"); self.assertTrue(r.body["link"].endswith("#i=" + r.body["code"]))
        toks = []
        for ua in ("phone", "laptop", "tablet"):
            s = self.svc.redeem(r.body["code"].upper().replace("-", " "), ua, "1.1.1.1")     # forgiving input
            self.assertEqual(s.status, 200); self.assertEqual(s.body["role"], "guest"); toks.append(token_from(s))
        full = self.svc.redeem(r.body["code"], "fourth", "1.1.1.1")
        self.assertEqual((full.status, full.body["error"]), (403, "this invite is full. ask JC."))
        self.assertEqual(self.svc.verify(toks[0], "notes.example.com", "GET", "/", "text/html").status, 200)
        self.assertEqual(self.svc.verify(toks[0], "archive.example.com", "GET", "/", "text/html").status, 302)
        me = self.svc.me(toks[1]); self.assertEqual(me.body["expires"], r.body["expires"])
        self.assertEqual(token_from(me), toks[1]); self.assertIn(f"Max-Age={3 * DAY}", me.cookie)   # his invite's life, not a renewal
        self.clock.t += 3 * DAY + 1
        self.assertEqual(self.svc.me(toks[2]).status, 401)
        self.assertEqual(self.svc.redeem(r.body["code"], "late", "1.1.1.1").status, 401)

    def test_member_invite_enrolls_a_passkey_and_the_code_dies(self):
        r = self.svc.create_invite("jill", ["notes"], "30d", "member")
        self.assertEqual(r.status, 200)
        got = self.svc.redeem(r.body["code"], "iPhone", "2.2.2.2")
        self.assertEqual((got.status, got.body["kind"], got.body["name"]), (200, "member", "jill"))
        jill = SoftAuthenticator(CFG.rp_id, CFG.origin)
        o = self.svc.register_options(got.body["ticket"], None)
        v = self.svc.register_verify(o.body["challenge_id"], jill.register(o.body["options"]), got.body["ticket"], None, "iPhone")
        self.assertEqual((v.status, v.body["role"], v.body["sites"]), (200, "member", ["notes"]))
        self.assertEqual(self.svc.redeem(r.body["code"], "again", "2.2.2.2").status, 401)
        lo = self.svc.login_options("2.2.2.2")
        again = self.svc.login_verify(lo.body["challenge_id"], jill.authenticate(lo.body["options"]), "Mac", "2.2.2.2")
        self.assertEqual(again.status, 200); self.assertEqual(self.svc.verify(token_from(again), "photos.example.com", "GET", "/", "text/html").status, 302)

    def test_bad_input_is_refused_with_a_reason(self):
        for name, sites, ttl, kind, needle in (
            ("Bob!", ["notes"], "3d", "guest", "name"),
            ("bob", ["elsewhere"], "3d", "guest", "no such site: elsewhere"),
            ("bob", ["example.com"], "3d", "guest", "doesn't need granting"),
            ("bob", [], "3d", "guest", "at least one site"),
            ("bob", ["notes"], "2w", "guest", "ttl"),
            ("bob", ["notes"], "3d", "vip", "kind"),
        ):
            r = self.svc.create_invite(name, sites, ttl, kind)
            self.assertEqual(r.status, 400, (name, sites, ttl, kind)); self.assertIn(needle, r.body["error"])

    def test_apex_and_unknown_site_are_refused_with_different_reasons(self):
        """The apex is refused because granting it would be meaningless -- every signed-in session
        can already reach it, since it hosts the terminal -- not because example.com isn't a
        real site. Sharing wording with an unknown name would tell the owner guests can't reach the
        apex at all, when they always could, so the two refusals must read differently."""
        apex = self.svc.create_invite("bob", ["example.com"], "3d", "guest")
        unknown = self.svc.create_invite("bob", ["elsewhere"], "3d", "guest")
        self.assertEqual((apex.status, unknown.status), (400, 400))
        self.assertNotEqual(apex.body["error"], unknown.body["error"])
        self.assertNotIn("no such site", apex.body["error"])
        self.assertIn("no such site", unknown.body["error"])

    def test_names_keep_their_role_and_owner_name_is_reserved(self):
        self.store.create_user("ada", "owner", ["*"], self.clock())
        self.assertEqual(self.svc.create_invite("ada", ["notes"], "1d", "guest").status, 400)
        self.assertEqual(self.svc.create_invite("bob", ["notes"], "1d", "guest").status, 200)
        self.assertEqual(self.svc.create_invite("bob", ["photos"], "1d", "member").status, 400)
        r = self.svc.create_invite("bob", ["photos"], "1d", "guest")      # a second guest invite widens the list
        self.assertEqual(r.body["sites"], ["notes", "photos"])

    def test_default_ttl_is_seven_days_and_wrong_codes_are_rate_limited(self):
        r = self.svc.create_invite("bob", ["notes"], None, "guest")
        self.assertEqual(r.body["expires"], int(self.clock() + 7 * DAY))
        for _ in range(10):
            self.assertEqual(self.svc.redeem("nope-nope-nope-00", "x", "3.3.3.3").status, 401)
        self.assertEqual(self.svc.redeem(r.body["code"], "x", "3.3.3.3").status, 429)
        self.assertEqual(self.svc.redeem(r.body["code"], "x", "4.4.4.4").status, 200)

    def test_holding_a_good_code_does_not_reset_the_failure_counter(self):
        """The brute-force control is the only thing standing between a ~30-bit invite code and an
        exhaustive search, so a redemption that works must not buy the caller a fresh budget of
        guesses. Somebody holding one legitimate invite can otherwise interleave nine wrong codes
        with one redemption of their own and never be throttled at all."""
        good = self.svc.create_invite("bob", ["notes"], "3d", "guest")
        ip = "5.6.7.8"
        for i in range(RATE_LIMIT):
            self.assertEqual(self.svc.redeem(f"nope-nope-nope-{i:02d}", "x", ip).status, 401)
            if i == 4:                                          # their own code, mid-run
                self.assertEqual(self.svc.redeem(good.body["code"], "x", ip).status, 200)
        self.assertEqual(self.svc.redeem("nope-nope-nope-99", "x", ip).status, 429)
        self.assertEqual(self.svc.redeem(good.body["code"], "x", ip).status, 429)
        self.assertEqual(self.svc.redeem(good.body["code"], "x", "5.6.7.9").status, 200)   # a different caller is untouched

    def test_a_full_invite_is_a_failed_try_like_any_other_refusal(self):
        """A refusal is a refusal: guessing at a code whose browsers are all used up is still
        guessing, and must cost the caller from the same budget as a wrong code."""
        r = self.svc.create_invite("amy", ["notes"], "3d", "guest")
        ip = "6.7.8.9"
        for ua in ("phone", "laptop", "tablet"):
            self.assertEqual(self.svc.redeem(r.body["code"], ua, ip).status, 200)
        for _ in range(RATE_LIMIT):
            self.assertEqual(self.svc.redeem(r.body["code"], "fourth", ip).status, 403)
        self.assertEqual(self.svc.redeem(r.body["code"], "fourth", ip).status, 429)

    def test_claiming_a_guest_invites_browser_slot_is_atomic_and_caps_at_max(self):
        """The backstop the three-browser cap relies on: claiming a slot is one conditional UPDATE,
        not a read-compare-then-write, so browsers_used can never be pushed past max_browsers no
        matter how many callers race for the last slot."""
        u = self.store.create_user("amy", "guest", ["notes.example.com"], self.clock())
        inv = self.store.create_invite("a-b-c-09", u.id, "guest", self.clock() + DAY, self.clock(), max_browsers=3)
        self.assertTrue(self.store.claim_invite_browser(inv.id))
        self.assertTrue(self.store.claim_invite_browser(inv.id))
        self.assertTrue(self.store.claim_invite_browser(inv.id))
        self.assertFalse(self.store.claim_invite_browser(inv.id))
        self.assertFalse(self.store.claim_invite_browser(inv.id))
        self.assertEqual(self.store.invite_by_id(inv.id).browsers_used, 3)

    def test_a_one_site_invite_links_straight_to_that_site(self):
        """The gap the first deployment found: the runbook promised a notes-only guest would land
        on notes, and every redemption landed on the terminal instead, because the link named no
        destination and the page fell back to the site root. Someone whose whole world is one site
        should never have to learn the terminal exists."""
        for kind in ("guest", "member"):
            with self.subTest(kind=kind):
                r = self.svc.create_invite(f"solo{kind}", ["notes"], "3d", kind)
                self.assertEqual(r.body["link"],
                                 f"{CFG.origin}{CFG.login_path}?next=https%3A%2F%2Fnotes.example.com%2F#i={r.body['code']}")

    def test_a_multi_site_invite_carries_no_destination(self):
        """Two sites and there is no single right answer, so the link stays bare and lands on the
        terminal — which is where somebody with a choice to make should start."""
        r = self.svc.create_invite("bob", ["notes", "photos"], "3d", "guest")
        self.assertEqual(r.body["link"], f"{CFG.origin}{CFG.login_path}#i={r.body['code']}")
        self.assertNotIn("next", r.body["link"])

    def test_widening_a_guest_to_a_second_site_drops_the_destination(self):
        """The destination follows what redeeming actually gets you, not what this one invite named:
        a second invite widens the same user's list, and from then on the terminal is the honest
        landing place."""
        first = self.svc.create_invite("bob", ["notes"], "1d", "guest")
        self.assertIn("next=https%3A%2F%2Fnotes.example.com%2F", first.body["link"])
        second = self.svc.create_invite("bob", ["photos"], "1d", "guest")
        self.assertEqual(second.body["sites"], ["notes", "photos"])
        self.assertEqual(second.body["link"], f"{CFG.origin}{CFG.login_path}#i={second.body['code']}")

    def test_the_owner_enrollment_link_never_carries_a_destination(self):
        """The owner's site list is the single entry `*`, which is a wildcard and not a host. Counting
        entries without asking whether they are hosts would put `https://*/` in front of the browser
        holding the only key to all five sites."""
        e = self.svc.enroll_owner()
        self.assertEqual(e.body["link"], f"{CFG.origin}{CFG.login_path}#i={e.body['code']}")

    def test_the_link_is_shaped_the_way_the_login_page_reads_one(self):
        """Shape first, then contents. The page takes the code from the fragment and the destination
        from the query, and once it has the code it scrubs the address bar by rewriting the URL as
        path + search — so a destination in the fragment would be thrown away with the code, and a
        code in the query would be written into every server log between here and the browser."""
        r = self.svc.create_invite("bob", ["photos"], "3d", "guest")
        url, sep, fragment = r.body["link"].partition("#")
        parts = urlsplit(url)
        self.assertEqual((sep, fragment), ("#", "i=" + r.body["code"]), "the code must ride in the fragment")
        self.assertNotIn(r.body["code"], url, "nothing before the fragment may carry the code")
        self.assertEqual(parts.path, CFG.login_path)
        self.assertIn("next=", parts.query, "the destination must survive the page's path + search scrub")
        destination = dict(parse_qsl(parts.query))["next"]           # what params.get("next") hands dest()
        self.assertEqual(destination, "https://photos.example.com/")
        for requirement, holds in LOGIN_PAGE_NEXT_RULES:
            with self.subTest(requirement=requirement):
                self.assertTrue(holds(destination), f"the page would refuse this and fall back to the site root: {requirement}")
