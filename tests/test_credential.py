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
    """Mutating the payload while keeping it parseable must surface as
    ``InvalidSignature``, not ``MalformedCredential``.

    The earlier test accepted either, which let a regression where
    tampering corrupted the JSON (rather than failing the signature
    check) pass for the wrong reason. Here we mutate a single character
    inside the ``user`` field so the payload remains valid JSON with all
    fields present — the only check that can reject it is the signature.
    """
    import base64
    import json

    key = SigningKey.generate()
    signed = sign(_make_credential(user="alice@example.com"), key)
    encoded = signed.encode()
    payload_b64, sig_b64 = encoded.split(".", 1)

    # Decode payload, mutate user field deterministically, re-encode. The
    # signature still references the original bytes, so verification must
    # raise InvalidSignature specifically.
    payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    body = json.loads(payload_bytes.decode("utf-8"))
    body["user"] = "mallory@example.com"
    tampered_bytes = json.dumps(body, sort_keys=True).encode("utf-8")
    tampered_b64 = base64.urlsafe_b64encode(tampered_bytes).rstrip(b"=").decode("ascii")
    tampered = f"{tampered_b64}.{sig_b64}"

    with pytest.raises(InvalidSignature):
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
        "invocation_id",
    ):
        assert required_key in payload, f"missing {required_key} in signed payload"


def test_invocation_id_round_trips_through_signing() -> None:
    """The gateway-supplied invocation_id is part of the signed payload."""
    key = SigningKey.generate()
    credential = _make_credential(invocation_id="inv-abc-123")
    signed = sign(credential, key)
    recovered = verify_signature(signed.encode(), key.verify_key)
    assert recovered.invocation_id == "inv-abc-123"


def test_signed_credential_is_a_value_type() -> None:
    """``SignedCredential`` should be hashable / comparable by value."""
    key = SigningKey.generate()
    credential = _make_credential()
    a = sign(credential, key)
    b = SignedCredential(credential=a.credential, signature=a.signature)
    assert a == b


def test_scoped_credential_is_frozen() -> None:
    """The dataclass is ``frozen=True`` — fields cannot be reassigned.

    Pins the contract that once signed, a credential cannot be mutated
    in place. Without this, a buggy caller could change ``action`` after
    signing and then claim the credential covered the new action — the
    signature would still verify against the original payload, but the
    in-memory object would lie about its own contents.
    """
    from dataclasses import FrozenInstanceError

    credential = _make_credential()
    with pytest.raises(FrozenInstanceError):
        credential.action = "delete"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        credential.user = "mallory@example.com"  # type: ignore[misc]
