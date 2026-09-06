"""Thin wrappers over py_webauthn so the rest of the service never sees its types."""
from __future__ import annotations

from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (AttestationConveyancePreference, AuthenticatorSelectionCriteria,
                                      PublicKeyCredentialDescriptor, ResidentKeyRequirement, UserVerificationRequirement)


def registration_options(cfg, user_id: bytes, name: str, exclude: list) -> tuple:
    opts = generate_registration_options(
        rp_id=cfg.rp_id, rp_name=cfg.rp_name, user_id=user_id, user_name=name, user_display_name=name,
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED),
        attestation=AttestationConveyancePreference.NONE,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c) for c in exclude],
    )
    return opts.challenge, options_to_json(opts)


def verify_registration(cfg, credential: dict, challenge: bytes) -> tuple:
    v = verify_registration_response(credential=credential, expected_challenge=challenge, expected_rp_id=cfg.rp_id,
                                     expected_origin=cfg.origin, require_user_verification=True)
    return v.credential_id, v.credential_public_key, v.sign_count


def authentication_options(cfg) -> tuple:
    opts = generate_authentication_options(rp_id=cfg.rp_id, user_verification=UserVerificationRequirement.REQUIRED)
    return opts.challenge, options_to_json(opts)


def verify_authentication(cfg, credential: dict, challenge: bytes, public_key: bytes, sign_count: int) -> tuple:
    """Returns (new_sign_count, counter_warning). Synced passkeys do not keep a counter, so a stale one is logged, not fatal.

    We always verify with credential_current_sign_count=0 so the library never raises on the counter
    itself (a genuine signature/challenge/origin failure still raises normally). The warning is then
    computed from the stored and returned counts: a counter is stale when it fails to advance past a
    stored count that was itself non-zero (a stored count of 0 means we have never seen this
    credential authenticate before, so a returned count of 0 or more is not evidence of staleness).
    """
    result = verify_authentication_response(
        credential=credential, expected_challenge=challenge, expected_rp_id=cfg.rp_id, expected_origin=cfg.origin,
        credential_public_key=public_key, credential_current_sign_count=0, require_user_verification=True,
    )
    counter_warning = sign_count != 0 and result.new_sign_count <= sign_count
    return result.new_sign_count, counter_warning


def credential_id_bytes(credential: dict) -> bytes:
    return base64url_to_bytes(credential.get("rawId") or credential["id"])
