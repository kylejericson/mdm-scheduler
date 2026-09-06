"""A software authenticator, so the passkey flows can be tested end to end.

Mocking py_webauthn's verification would only prove that the mock returns what
the test told it to. This produces real attestation objects and real ECDSA
assertions, so the library does its actual work and a mistake in how the app
frames a ceremony - wrong origin, wrong RP ID, reused challenge - fails the
test rather than passing it.
"""

from __future__ import annotations

import json
import os
import struct
from hashlib import sha256

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

AAGUID = b"\x00" * 16

FLAG_UP = 0x01  # user present
FLAG_UV = 0x04  # user verified
FLAG_AT = 0x40  # attested credential data included


class FakeAuthenticator:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    # ---------------------------------------------------------------- helpers
    def _rp_hash(self, rp_id: str | None = None) -> bytes:
        return sha256((rp_id or self.rp_id).encode()).digest()

    def _cose_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _client_data(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()

    # ----------------------------------------------------------- registration
    def register(self, options: dict, origin: str | None = None, rp_id: str | None = None) -> dict:
        challenge = options["challenge"]
        client_data = self._client_data("webauthn.create", challenge, origin)

        auth_data = (
            self._rp_hash(rp_id)
            + bytes([FLAG_UP | FLAG_UV | FLAG_AT])
            + struct.pack(">I", self.sign_count)
            + AAGUID
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_key()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    # --------------------------------------------------------- authentication
    def authenticate(
        self,
        options: dict,
        origin: str | None = None,
        rp_id: str | None = None,
        bump: int = 1,
    ) -> dict:
        challenge = options["challenge"]
        client_data = self._client_data("webauthn.get", challenge, origin)

        self.sign_count += bump
        auth_data = (
            self._rp_hash(rp_id)
            + bytes([FLAG_UP | FLAG_UV])
            + struct.pack(">I", self.sign_count)
        )

        der = self.key.sign(auth_data + sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        decode_dss_signature(der)  # sanity: it really is a DSS signature

        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(der),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }

    def public_pem(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def decode_options(payload: dict) -> dict:
    """Options come back as WebAuthn JSON; the fake wants the same shape."""
    assert base64url_to_bytes(payload["challenge"])  # must be valid base64url
    return payload
