"""Gateway-layer tests.

The gateway is the enforcement point: it consults policy, applies TTL
obligations, signs a credential, and emits an audit record. Tests pin:

- An allowed request produces a verified, signed credential.
- A denied request raises ``IssuanceDenied`` and emits a denial audit.
- The gateway clamps TTL to the smaller of the ceiling and the policy's
  ``max_ttl`` obligation (defense in depth).
- Each issuance emits exactly one ``credential.issued`` audit event.
"""

from __future__ import annotations

import time

import pytest

from aim.audit import InMemoryAuditSink
from aim.credential import verify_signature
from aim.gateway import CredentialGateway, IssuanceDenied
from aim.policy import Decision, RequestContext


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


def test_allowed_request_issues_a_verified_credential(
    gateway: CredentialGateway,
) -> None:
    signed = gateway.issue(_ctx())

    # The credential round-trips through the gateway's verify key.
    recovered = verify_signature(signed.encode(), gateway.verify_key)
    assert recovered.user == "alice@example.com"
    assert recovered.tool == "issues"
    assert recovered.action == "list"
    assert recovered.expires_at > time.time()


def test_allowed_request_emits_credential_issued_audit(
    gateway: CredentialGateway,
    audit: InMemoryAuditSink,
) -> None:
    gateway.issue(_ctx())
    issued = audit.by_kind("credential.issued")

    assert len(issued) == 1
    assert issued[0].user == "alice@example.com"
    assert issued[0].action == "list"
    assert issued[0].outcome == "issued"
    assert issued[0].credential_id is not None


def test_denied_request_raises_and_audits(
    gateway: CredentialGateway,
    audit: InMemoryAuditSink,
) -> None:
    with pytest.raises(IssuanceDenied):
        gateway.issue(_ctx(action="delete"))

    denied = audit.by_kind("policy.denied")
    issued = audit.by_kind("credential.issued")

    assert len(denied) == 1
    assert denied[0].outcome == "denied"
    assert "delete" in (denied[0].reason or "")
    assert issued == []  # no credential ever minted on denial


def test_ttl_is_clamped_to_the_smaller_of_ceiling_and_obligation(
    gateway: CredentialGateway,
) -> None:
    """Defense in depth: a buggy obligation cannot extend TTL past the ceiling.

    The policy obligation says ``max_ttl=30`` for ``list``; the gateway's
    ceiling defaults to 60. The effective TTL is the smaller of the two.
    """
    signed = gateway.issue(_ctx(action="list"))
    issued_at = signed.credential.issued_at
    expires_at = signed.credential.expires_at

    # 30s obligation should win over 60s ceiling.
    assert expires_at - issued_at == pytest.approx(30.0, abs=0.5)


def test_explicit_ceiling_below_obligation_wins() -> None:
    """If the gateway's ceiling is lower than the policy's max_ttl, ceiling wins."""
    from nacl.signing import SigningKey

    from aim.policy import HardcodedPolicy

    audit = InMemoryAuditSink()
    gateway = CredentialGateway(
        signing_key=SigningKey.generate(),
        policy=HardcodedPolicy(),
        audit=audit,
        ttl_ceiling_seconds=5.0,  # below the policy's max_ttl=30 for list
    )

    signed = gateway.issue(_ctx(action="list"))
    assert signed.credential.expires_at - signed.credential.issued_at == pytest.approx(5.0, abs=0.5)


def test_unknown_obligations_do_not_break_issuance(
    gateway: CredentialGateway,
) -> None:
    """Forward compatibility: unrecognized obligations are ignored, not fatal."""

    class WeirdPolicy:
        def evaluate(self, ctx: RequestContext) -> Decision:
            return Decision(
                allow=True,
                reason="permitted",
                obligations=("audit_required", "unknown_directive=42", "max_ttl=15"),
            )

    gateway.policy = WeirdPolicy()
    signed = gateway.issue(_ctx())
    assert signed.credential.expires_at - signed.credential.issued_at == pytest.approx(
        15.0, abs=0.5
    )


def test_malformed_max_ttl_zero_is_denied_not_silently_dropped(
    gateway: CredentialGateway, audit: InMemoryAuditSink
) -> None:
    """``max_ttl=0`` is a malformed obligation; the gateway denies issuance.

    The earlier behavior was to leak a raw ``ValueError`` from
    ``ScopedCredential.issue``. The fix: convert into ``IssuanceDenied``
    with an explicit reason, and audit the denial.
    """

    class ZeroTtlPolicy:
        def evaluate(self, ctx: RequestContext) -> Decision:
            return Decision(allow=True, reason="permitted", obligations=("max_ttl=0",))

    gateway.policy = ZeroTtlPolicy()
    with pytest.raises(IssuanceDenied, match="malformed policy obligation"):
        gateway.issue(_ctx())

    denied = audit.by_kind("policy.denied")
    assert len(denied) == 1
    assert "max_ttl=0" in (denied[0].reason or "")
    assert audit.by_kind("credential.issued") == []


def test_malformed_max_ttl_negative_is_denied_not_silently_dropped(
    gateway: CredentialGateway, audit: InMemoryAuditSink
) -> None:
    """A negative ``max_ttl`` is malformed and rejected — not ignored.

    The earlier behavior was for the regex to silently fail to match
    negative values, leaving the ceiling as the effective TTL. Defense
    in depth means tighter bounds win — and an unparseable bound is
    treated as a policy bug, not a permission to relax.
    """

    class NegativeTtlPolicy:
        def evaluate(self, ctx: RequestContext) -> Decision:
            return Decision(allow=True, reason="permitted", obligations=("max_ttl=-30",))

    gateway.policy = NegativeTtlPolicy()
    with pytest.raises(IssuanceDenied, match="malformed policy obligation"):
        gateway.issue(_ctx())

    denied = audit.by_kind("policy.denied")
    assert len(denied) == 1
    assert "max_ttl=-30" in (denied[0].reason or "")


def test_unparseable_max_ttl_is_denied(
    gateway: CredentialGateway, audit: InMemoryAuditSink
) -> None:
    """A ``max_ttl=`` value that isn't a number is rejected explicitly."""

    class GarbageTtlPolicy:
        def evaluate(self, ctx: RequestContext) -> Decision:
            return Decision(allow=True, reason="permitted", obligations=("max_ttl=abc",))

    gateway.policy = GarbageTtlPolicy()
    with pytest.raises(IssuanceDenied, match="malformed policy obligation"):
        gateway.issue(_ctx())


def test_invocation_id_threads_through_audit_chain(
    gateway: CredentialGateway, audit: InMemoryAuditSink
) -> None:
    """Every audit event for one issuance shares an invocation_id.

    The case study claims the audit chain ties events back to a single
    agent action. This test pins the explicit linkage rather than
    relying on credential_id + timestamp ordering.
    """
    signed = gateway.issue(_ctx())

    issued = audit.by_kind("credential.issued")
    assert len(issued) == 1
    assert issued[0].invocation_id is not None
    assert signed.credential.invocation_id == issued[0].invocation_id


def test_distinct_issuances_get_distinct_invocation_ids(
    gateway: CredentialGateway,
) -> None:
    a = gateway.issue(_ctx())
    b = gateway.issue(_ctx())
    assert a.credential.invocation_id != b.credential.invocation_id
