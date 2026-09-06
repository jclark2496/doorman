import json, unittest
from doorman import passkeys
from doorman.config import Config
from tests.softauth import SoftAuthenticator

CFG = Config.from_env({})


class PasskeyTest(unittest.TestCase):
    def test_register_then_authenticate_round_trip(self):
        auth = SoftAuthenticator(CFG.rp_id, CFG.origin)
        challenge, options = passkeys.registration_options(CFG, b"1", "ada", [])
        opts = json.loads(options)
        self.assertEqual(opts["rp"]["id"], "example.com"); self.assertEqual(opts["authenticatorSelection"]["residentKey"], "required")
        self.assertEqual(opts["authenticatorSelection"]["userVerification"], "required"); self.assertEqual(opts["attestation"], "none")
        cred_id, public_key, count = passkeys.verify_registration(CFG, auth.register(opts), challenge)
        self.assertEqual(cred_id, auth.cred_id); self.assertEqual(count, 0); self.assertTrue(public_key)
        self.assertEqual(passkeys.credential_id_bytes(auth.register(opts)), auth.cred_id)
        challenge2, options2 = passkeys.authentication_options(CFG)
        opts2 = json.loads(options2); self.assertEqual(opts2.get("allowCredentials", []), [])
        new_count, warned = passkeys.verify_authentication(CFG, auth.authenticate(opts2), challenge2, public_key, 0)
        self.assertEqual((new_count, warned), (1, False))

    def test_wrong_challenge_or_origin_fails(self):
        auth = SoftAuthenticator(CFG.rp_id, CFG.origin)
        challenge, options = passkeys.registration_options(CFG, b"1", "ada", [])
        _, public_key, _ = passkeys.verify_registration(CFG, auth.register(json.loads(options)), challenge)
        c2, o2 = passkeys.authentication_options(CFG)
        with self.assertRaises(Exception):
            passkeys.verify_authentication(CFG, auth.authenticate(json.loads(o2)), b"not-the-challenge", public_key, 0)
        evil = SoftAuthenticator(CFG.rp_id, "https://evil.example"); evil.key = auth.key; evil.cred_id = auth.cred_id
        c3, o3 = passkeys.authentication_options(CFG)
        with self.assertRaises(Exception):
            passkeys.verify_authentication(CFG, evil.authenticate(json.loads(o3)), c3, public_key, 0)

    def test_stale_sign_counter_is_a_warning_not_a_failure(self):
        auth = SoftAuthenticator(CFG.rp_id, CFG.origin)
        challenge, options = passkeys.registration_options(CFG, b"1", "ada", [])
        _, public_key, _ = passkeys.verify_registration(CFG, auth.register(json.loads(options)), challenge)
        c, o = passkeys.authentication_options(CFG)
        new_count, warned = passkeys.verify_authentication(CFG, auth.authenticate(json.loads(o)), c, public_key, 7)
        self.assertEqual((new_count, warned), (1, True))

    def test_exclude_list_is_passed_through(self):
        _, options = passkeys.registration_options(CFG, b"1", "ada", [b"abc"])
        self.assertEqual(len(json.loads(options)["excludeCredentials"]), 1)
