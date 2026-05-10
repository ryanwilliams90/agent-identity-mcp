"""End-to-end tests: the full chain from policy decision to audit record.

The chain under test:

    user intent
    → gateway (policy.evaluate → sign credential → audit)
    → tool server invoke
    → verifier (signature, audience, action, expiry, replay → audit)
    → tool handler
    → audit completion

Each test exercises the whole chain for a specific outcome and pins
the audit shape so a downstream consumer can reconstruct what happened
from the events alone.

These tests pin two of the case study's central operational claims:

- A denied policy still produces an audit record (denials are part of
  the trust chain and have to be explainable later).
- The tool code is not reached when verification fails — the audit has
  a rejection event but no ``tool.invoked`` for the rejected action.
"""

from __future__ import annotations

import pytest

from aim.audit import InMemoryAuditSink
from aim.gateway import CredentialGateway, IssuanceDenied
from aim.policy import RequestContext
from aim.tool_server import ToolServer
from aim.verifier import ActionMismatch


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


def test_full_happy_path(
    gateway: CredentialGateway,
    tool_server: ToolServer,
    audit: InMemoryAuditSink,
) -> None:
    signed = gateway.issue(_ctx(action="list"))
    result = tool_server.invoke(action="list", encoded_credential=signed.encode())

    assert isinstance(result, list)
    assert len(result) == 3

    kinds = [e.kind for e in audit.events]
    assert kinds == [
        "credential.issued",
        "tool.invoked",
        "tool.completed",
    ]
    # Every event in the chain carries the same credential id.
    cred_ids = {e.credential_id for e in audit.events}
    assert len(cred_ids) == 1
    assert next(iter(cred_ids)) is not None


def test_denied_policy_chain(gateway: CredentialGateway, audit: InMemoryAuditSink) -> None:
    """A denied request emits a denial audit record and never mints a credential."""
    with pytest.raises(IssuanceDenied):
        gateway.issue(_ctx(action="delete"))

    kinds = [e.kind for e in audit.events]
    assert kinds == ["policy.denied"]
    denial = audit.events[0]
    assert denial.outcome == "denied"
    assert denial.user == "alice@example.com"
    assert denial.action == "delete"
    assert denial.credential_id is None  # no credential was ever minted


def test_tool_code_is_not_reached_when_verification_fails(
    gateway: CredentialGateway,
    tool_server: ToolServer,
    audit: InMemoryAuditSink,
) -> None:
    """The headline structural guarantee.

    A credential issued for ``list`` is presented in a request for
    ``read``. The verifier rejects. The audit shows the rejection. The
    audit does NOT show a ``tool.invoked`` for the read attempt — the
    handler was never called.
    """
    signed = gateway.issue(_ctx(action="list"))

    with pytest.raises(ActionMismatch):
        tool_server.invoke(
            action="read",
            encoded_credential=signed.encode(),
            arguments={"issue_id": "ISS-1"},
        )

    kinds = [e.kind for e in audit.events]
    assert kinds == [
        "credential.issued",  # issuance for "list"
        "verifier.rejected",  # rejection of the "read" attempt
    ]
    # The structural claim: no tool.invoked, no tool.completed.
    assert "tool.invoked" not in kinds
    assert "tool.completed" not in kinds


def test_invocation_id_links_full_chain(
    gateway: CredentialGateway,
    tool_server: ToolServer,
    audit: InMemoryAuditSink,
) -> None:
    """All four events of one happy path share a single invocation_id."""
    gateway.issue(_ctx(action="list"))
    # The signed credential carries the invocation_id; reuse it via the
    # full-flow path to make the linkage observable end to end.
    signed = gateway.issue(_ctx(action="list"))
    tool_server.invoke(action="list", encoded_credential=signed.encode())

    # Find the issuance event matching this credential's invocation_id.
    invocation_id = signed.credential.invocation_id
    matching = [e for e in audit.events if e.invocation_id == invocation_id]

    # Issuance, tool.invoked, tool.completed — three events, same
    # invocation id.
    assert {e.kind for e in matching} == {
        "credential.issued",
        "tool.invoked",
        "tool.completed",
    }


def test_invocation_id_links_rejection_to_issuance(
    gateway: CredentialGateway,
    tool_server: ToolServer,
    audit: InMemoryAuditSink,
) -> None:
    """A verifier rejection carries the same invocation_id as the issuance.

    This is the audit-causality property: a downstream consumer can ask
    'what happened to invocation X?' and get both events back without
    needing timestamp ordering.
    """
    signed = gateway.issue(_ctx(action="list"))
    invocation_id = signed.credential.invocation_id

    with pytest.raises(ActionMismatch):
        tool_server.invoke(
            action="read",  # mismatch
            encoded_credential=signed.encode(),
            arguments={"issue_id": "ISS-1"},
        )

    matching = [e for e in audit.events if e.invocation_id == invocation_id]
    kinds = {e.kind for e in matching}
    assert kinds == {"credential.issued", "verifier.rejected"}
