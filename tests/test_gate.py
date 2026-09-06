import unittest
from doorman.gate import decide
from doorman.store import Session, User

APEX = "example.com"
def sess(expires=1000.0, revoked=None, invite=None): return Session(1, "h", 1, invite, 0.0, 0.0, expires, "", revoked)
def user(role="member", sites=("notes.example.com",), disabled=False): return User(1, "jill", role, list(sites), disabled)


class GateTest(unittest.TestCase):
    def test_no_session_is_401(self):
        self.assertEqual(decide(None, None, "notes.example.com", 10.0, APEX).status, 401)

    def test_expired_revoked_or_disabled_is_401(self):
        self.assertEqual(decide(user(), sess(expires=5.0), "notes.example.com", 10.0, APEX).status, 401)
        self.assertEqual(decide(user(), sess(revoked=3.0), "notes.example.com", 10.0, APEX).status, 401)
        self.assertEqual(decide(user(disabled=True), sess(), "notes.example.com", 10.0, APEX).status, 401)

    def test_disabled_or_revoked_or_expired_owner_is_still_401(self):
        # Owner bypasses the site-list check entirely, so it is the one role where a login-state
        # bug would be most dangerous: a disabled/revoked/expired owner must still be refused,
        # even against a host ("archive.example.com") the owner would otherwise be allowed to see.
        self.assertEqual(decide(user("owner", ["*"], disabled=True), sess(), "archive.example.com", 10.0, APEX).status, 401)
        self.assertEqual(decide(user("owner", ["*"]), sess(revoked=3.0), "archive.example.com", 10.0, APEX).status, 401)
        self.assertEqual(decide(user("owner", ["*"]), sess(expires=5.0), "archive.example.com", 10.0, APEX).status, 401)

    def test_owner_goes_anywhere(self):
        d = decide(user("owner", ["*"]), sess(), "archive.example.com", 10.0, APEX)
        self.assertEqual((d.status, d.user, d.role), (200, "jill", "owner"))

    def test_member_and_guest_only_their_sites_plus_the_apex(self):
        self.assertEqual(decide(user(), sess(), "notes.example.com", 10.0, APEX).status, 200)
        self.assertEqual(decide(user(), sess(), "NOTES.example.com:443", 10.0, APEX).status, 200)
        self.assertEqual(decide(user(), sess(), APEX, 10.0, APEX).status, 200)
        self.assertEqual(decide(user(), sess(), "photos.example.com", 10.0, APEX).status, 403)
        self.assertEqual(decide(user("guest"), sess(invite=7), "photos.example.com", 10.0, APEX).status, 403)
