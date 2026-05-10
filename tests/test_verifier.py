"""Verifier tests — the security properties at the heart of the design.

Each rejection reason is exercised separately so failures point at a
single root cause. Every rejection emits a ``verifier.rejected`` audit
event with the appropriate ``outcome`` code; a downstream consumer can
distinguish these without parsing free-form text.

These tests pin the eight properties the case study claims:

- valid credential succeeds
- wrong action rejected
- wrong audience rejected
- expired credential rejected
- tampered credential rejected
- replay rejected
- bad signature rejected
- malformed credential rejected
"""

from __future__ import annotations

import time

import pytest
from nacl.signing import SigningKey

from aim.audit import InMemoryAuditSink
from aim.credential import ScopedCredential, sign
from aim.gateway import CredentialGateway
from aim.policy import RequestContext
from aim.verifier import (
    ActionMismatch,
    AudienceMismatch,
    BadCredential,
    CredentialExpired,
    CredentialReplayed,
    Verifier,
)


def _ctx(**overrides: str) -> RequestContext:
    defaults: dict[str, str] = {
        "user": "alice@example.com",
        "agent": "agent-runtime-A",
        "task": "task-001",
        "tool": "issues",
        "action": "list",
        "audience": "tool-server.issues",
        "environment": "prod",
    }
    defaults.update(overrides)
    return RequestContext(**defaults)


# ---- Happy path ---------------------------------------------------------


def test_valid_credential_succeeds(gateway: CredentialGateway, verifier: Verifier) -> None:
    signed = gateway.issue(_ctx())
    credential = verifier.verify(
        signed.encode(),
        requested_action="list",
        requested_tool="issues",
    )
    assert credential.user == "alice@example.com"
    assert credential.action == "list"


# ---- Rejection paths ----------------------------------------------------


def test_wrong_action_rejected(
    gateway: CredentialGateway, verifier: Verifier, audit: InMemoryAuditSink
) -> None:
    """Credential issued for ``list``, request claims ``read``: rejected."""
    signed = gateway.issue(_ctx(action="list"))
    with pytest.raises(ActionMismatch):
        verifier.verify(
            signed.encode(),
            requested_action="read",
            requested_tool="issues",
        )

    rejections = audit.by_kind("verifier.rejected")
    assert len(rejections) == 1
    assert rejections[0].outcome == "action_mismatch"


def test_wrong_tool_rejected_as_action_mismatch(
    gateway: CredentialGateway, verifier: Verifier
) -> None:
    """Credential is bound to ``tool=issues``; request for ``tool=secrets`` rejects."""
    signed = gateway.issue(_ctx())
    with pytest.raises(ActionMismatch):
        verifier.verify(
            signed.encode(),
            requested_action="list",
            requested_tool="secrets",
        )


def test_wrong_audience_rejected(
    gateway: CredentialGateway,
    signing_key: SigningKey,
    audit: InMemoryAuditSink,
) -> None:
    """Verifier configured for one audience rejects credentials minted for another."""
    signed = gateway.issue(_ctx(audience="tool-server.issues"))

    other_verifier = Verifier(
        verify_key=signing_key.verify_key,
        audience="tool-server.deployments",  # different audience
        audit=audit,
    )
    with pytest.raises(AudienceMismatch):
        other_verifier.verify(
            signed.encode(),
            requested_action="list",
            requested_tool="issues",
        )

    rejections = audit.by_kind("verifier.rejected")
    assert len(rejections) == 1
    assert rejections[0].outcome == "audience_mismatch"


def test_expired_credential_rejected(
    signing_key: SigningKey,
    verifier: Verifier,
    audit: InMemoryAuditSink,
) -> None:
    """A credential whose expiry has passed is rejected even with valid signature."""
    # Build an already-expired credential by hand to avoid real-time waits.
    expired = ScopedCredential(
        credential_id="cred-expired",
        invocation_id="inv-expired",
        user="alice@example.com",
        agent="agent-runtime-A",
        task="task-001",
        tool="issues",
        action="list",
        audience="tool-server.issues",
        issued_at=time.time() - 120,
        expires_at=time.time() - 60,
        nonce="deadbeef" * 4,
    )
    signed = sign(expired, signing_key)

    with pytest.raises(CredentialExpired):
        verifier.verify(
            signed.encode(),
            requested_action="list",
            requested_tool="issues",
        )

    rejections = audit.by_kind("verifier.rejected")
    assert len(rejections) == 1
    assert rejections[0].outcome == "expired"


def test_tampered_credential_rejected(
    gateway: CredentialGateway,
    verifier: Verifier,
    audit: InMemoryAuditSink,
) -> None:
    """Mutating the encoded payload after signing causes rejection.

    Tampering raises one of two underlying credential errors —
    ``InvalidSignature`` (modified payload parses but fails signature
    verification) or ``MalformedCredential`` (modification produced
    invalid base64url or invalid JSON). Both surface to the caller as
    ``BadCredential``; that uniform shape is the verifier's contract.
    """
    signed = gateway.issue(_ctx())
    encoded = signed.encode()
    payload, sig = encoded.split(".", 1)
    tampered_payload = ("A" if not payload.startswith("A") else "B") + payload[1:]
    tampered = f"{tampered_payload}.{sig}"

    with pytest.raises(BadCredential):
        verifier.verify(
            tampered,
            requested_action="list",
            requested_tool="issues",
        )

    rejections = audit.by_kind("verifier.rejected")
    assert len(rejections) == 1
    assert rejections[0].outcome == "bad_credential"


def test_bad_signature_from_impostor_key_rejected(
    verifier: Verifier,
    audit: InMemoryAuditSink,
) -> None:
    """A credential signed by a different key is rejected as bad credential."""
    impostor = SigningKey.generate()
    credential = ScopedCredential.issue(
        user="mallory@example.com",
        agent="agent-runtime-X",
        task="task-attack",
        tool="issues",
        action="list",
        audience="tool-server.issues",
        ttl_seconds=30.0,
    )
    signed = sign(credential, impostor)

    with pytest.raises(BadCredential):
        verifier.verify(
            signed.encode(),
            requested_action="list",
            requested_tool="issues",
        )

    rejections = audit.by_kind("verifier.rejected")
    assert len(rejections) == 1
    assert rejections[0].outcome == "bad_credential"


def test_replay_rejected(
    gateway: CredentialGateway,
    verifier: Verifier,
    audit: InMemoryAuditSink,
) -> None:
    """A credential successfully verified once cannot be verified again."""
    signed = gateway.issue(_ctx())
    encoded = signed.encode()

    # First call accepts.
    verifier.verify(encoded, requested_action="list", requested_tool="issues")

    # Second call with the same credential is a replay.
    with pytest.raises(CredentialReplayed):
        verifier.verify(encoded, requested_action="list", requested_tool="issues")

    rejections = audit.by_kind("verifier.rejected")
    assert len(rejections) == 1
    assert rejections[0].outcome == "replayed"


def test_malformed_encoded_credential_rejected(
    verifier: Verifier, audit: InMemoryAuditSink
) -> None:
    """Junk in, typed BadCredential out, with an audit record."""
    with pytest.raises(BadCredential):
        verifier.verify(
            "this-is-not-a-credential",
            requested_action="list",
            requested_tool="issues",
        )

    rejections = audit.by_kind("verifier.rejected")
    assert len(rejections) == 1
    assert rejections[0].outcome == "bad_credential"
