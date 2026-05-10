"""Credential-layer tests.

These pin the signing/verification contract:

- A credential signed by the issuer verifies against the issuer's public key.
- Tampering with the payload invalidates the signature.
- A signature from a different key does not verify.
- The encoded form survives a round trip.
- Malformed encoded forms raise ``MalformedCredential``, not arbitrary errors.
"""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from aim.credential import (
    InvalidSignature,
    MalformedCredential,
    ScopedCredential,
    SignedCredential,
    sign,
    verify_signature,
)


def _make_credential(**overrides: object) -> ScopedCredential:
    defaults: dict[str, object] = {
        "user": "alice@example.com",
        "agent": "agent-runtime-A",
        "task": "task-001",
        "tool": "issues",
        "action": "list",
        "audience": "tool-server.issues",
        "ttl_seconds": 30.0,
    }
    defaults.update(overrides)
    return ScopedCredential.issue(**defaults)  # type: ignore[arg-type]


def test_signed_credential_round_trips() -> None:
    key = SigningKey.generate()
    credential = _make_credential()
    signed = sign(credential, key)

    encoded = signed.encode()
    recovered = verify_signature(encoded, key.verify_key)

    assert recovered == credential


def test_signature_does_not_verify_under_a_different_key() -> None:
    issuer = SigningKey.generate()
    impostor = SigningKey.generate()
    signed = sign(_make_credential(), issuer)

    with pytest.raises(InvalidSignature):
        verify_signature(signed.encode(), impostor.verify_key)


def test_tampered_payload_invalidates_signature() -> None:
    key = SigningKey.generate()
    signed = sign(_make_credential(), key)
    encoded = signed.encode()
    payload, sig = encoded.split(".", 1)

    # Flip a bit in the payload (deterministically — replace the first
    # ascii letter with one that differs but is still valid base64url).
    tampered_payload = ("A" if not payload.startswith("A") else "B") + payload[1:]
    tampered = f"{tampered_payload}.{sig}"

    with pytest.raises((InvalidSignature, MalformedCredential)):
        verify_signature(tampered, key.verify_key)


def test_malformed_encoded_credential_raises_typed_error() -> None:
    key = SigningKey.generate()
    with pytest.raises(MalformedCredential):
        verify_signature("not-an-encoded-credential", key.verify_key)


def test_malformed_payload_after_signature_verifies_raises_typed_error() -> None:
    """Even if the format parses, missing fields produce MalformedCredential."""
    import base64
    import json

    key = SigningKey.generate()
    incomplete = json.dumps({"user": "alice"}).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(incomplete).rstrip(b"=").decode("ascii")
    sig = key.sign(incomplete).signature
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    encoded = f"{payload_b64}.{sig_b64}"

    with pytest.raises(MalformedCredential):
        verify_signature(encoded, key.verify_key)


def test_scoped_credential_requires_positive_ttl() -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        _make_credential(ttl_seconds=0)


def test_scoped_credential_carries_all_identity_facets() -> None:
    """The signed payload includes every field a verifier would need."""
    credential = _make_credential()
    payload = credential.to_payload()

    for required_key in (
        "user",
        "agent",
        "task",
        "tool",
        "action",
        "audience",
        "issued_at",
        "expires_at",
        "nonce",
        "credential_id",
    ):
        assert required_key in payload, f"missing {required_key} in signed payload"


def test_signed_credential_is_a_value_type() -> None:
    """``SignedCredential`` should be hashable / comparable by value."""
    key = SigningKey.generate()
    credential = _make_credential()
    a = sign(credential, key)
    b = SignedCredential(credential=a.credential, signature=a.signature)
    assert a == b
