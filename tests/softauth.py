"""A tiny WebAuthn authenticator for tests: one ES256 key, `none` attestation, a sign counter.
Produces the JSON a browser would hand back from navigator.credentials.create() / .get()."""
from __future__ import annotations

import base64, hashlib, json, os, struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id, self.origin = rp_id, origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.user_handle: str | None = None
        self.count = 0

    def _cose_key(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def register(self, options: dict) -> dict:
        self.user_handle = options["user"]["id"]
        client_data = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": self.origin, "crossOrigin": False}).encode()
        auth_data = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + struct.pack(">I", 0)
                     + bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose_key())
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key", "authenticatorAttachment": "platform",
                "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(att), "transports": ["internal"]},
                "clientExtensionResults": {}}

    def authenticate(self, options: dict, bump: bool = True) -> dict:
        client_data = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": self.origin, "crossOrigin": False}).encode()
        if bump:
            self.count += 1
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.count)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data), "signature": b64u(signature), "userHandle": self.user_handle},
                "clientExtensionResults": {}}
