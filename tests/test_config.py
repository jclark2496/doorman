import unittest
from doorman.config import Config

ENV = {"AUTH_HOSTS": "example.com,notes.example.com,photos.example.com", "AUTH_SITE_ALIASES": "notes=notes.example.com,photos=photos.example.com"}


class ConfigTest(unittest.TestCase):
    def test_defaults(self):
        c = Config.from_env({})
        self.assertEqual(c.port, 8401); self.assertEqual(c.origin, "https://example.com"); self.assertEqual(c.rp_id, "example.com")
        self.assertEqual(c.cookie_domain, ".example.com"); self.assertEqual(c.cookie_name, "doorman_session")
        self.assertEqual(c.session_days, 30); self.assertEqual(c.renew_days, 15); self.assertEqual(c.owner_name, "ada")
        self.assertEqual(c.apex, "example.com"); self.assertEqual(c.hosts[1:], ["notes.example.com", "photos.example.com", "files.example.com", "archive.example.com"])

    def test_host_for_accepts_alias_or_host_and_rejects_unknown(self):
        c = Config.from_env(ENV)
        self.assertEqual(c.host_for("notes"), "notes.example.com")
        self.assertEqual(c.host_for("Photos.example.com"), "photos.example.com")
        self.assertIsNone(c.host_for("elsewhere.example.net"))
        self.assertIsNone(c.host_for("files"))

    def test_the_apex_comes_from_the_origin_not_from_the_order_of_the_host_list(self):
        """Every session may reach the apex, so which host that is must not depend on where someone
        happened to put it in AUTH_HOSTS: reordering the env file would otherwise silently open a
        different site to every guest."""
        c = Config.from_env({"AUTH_HOSTS": "notes.example.com,example.com,photos.example.com"})
        self.assertEqual(c.apex, "example.com")

    def test_a_host_list_that_cannot_serve_the_origin_is_refused_at_startup(self):
        """Both of these used to be found one request at a time -- an empty list raised on every
        request, and a list without the origin's host quietly denied the apex to everyone."""
        with self.assertRaises(ValueError):
            Config.from_env({"AUTH_HOSTS": ""})
        with self.assertRaises(ValueError):
            Config.from_env({"AUTH_HOSTS": "notes.example.com,photos.example.com"})
        self.assertEqual(Config.from_env({"AUTH_ORIGIN": "https://example.test", "AUTH_HOSTS": "example.test"}).apex, "example.test")
