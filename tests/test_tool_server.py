"""Tool server tests.

The structural property under test: tool code does not run unless the
verifier accepts the credential. Every rejection path exits the
``invoke`` method via the verifier's exception, before any handler is
called.

The happy-path test confirms the full chain works; the
escalation-attempt test is the prototype's headline demonstration —
a credential issued for ``list`` is rejected when used to call
``read``, *before* the read handler is reached.
"""

from __future__ import annotations

import pytest

from aim.audit import InMemoryAuditSink
from aim.gateway import CredentialGateway
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


def test_happy_path_returns_tool_output(
    gateway: CredentialGateway,
    tool_server: ToolServer,
    audit: InMemoryAuditSink,
) -> None:
    signed = gateway.issue(_ctx(action="list"))
    result = tool_server.invoke(action="list", encoded_credential=signed.encode())

    assert isinstance(result, list)
    assert all("issue_id" in item for item in result)

    # Audit chain: issuance, invocation, completion. No rejection.
    assert audit.by_kind("credential.issued")
    assert audit.by_kind("tool.invoked")
    assert audit.by_kind("tool.completed")
    assert audit.by_kind("verifier.rejected") == []


def test_escalation_attempt_is_rejected_before_tool_code_runs(
    gateway: CredentialGateway,
    tool_server: ToolServer,
    audit: InMemoryAuditSink,
) -> None:
    """The headline demonstration.

    A credential issued for ``list`` is presented in a request to call
    ``read``. The verifier rejects with ``ActionMismatch``; the read
    handler is never invoked. The audit chain shows the rejection but
    no ``tool.invoked`` event for the ``read`` action.
    """
    signed = gateway.issue(_ctx(action="list"))

    with pytest.raises(ActionMismatch):
        tool_server.invoke(
            action="read",  # different from the credential's action
            encoded_credential=signed.encode(),
            arguments={"issue_id": "ISS-1"},
        )

    # The verifier rejected the call.
    rejections = audit.by_kind("verifier.rejected")
    assert len(rejections) == 1
    assert rejections[0].outcome == "action_mismatch"
    assert rejections[0].action == "read"

    # And critically: no tool was invoked, no tool completed.
    assert audit.by_kind("tool.invoked") == []
    assert audit.by_kind("tool.completed") == []


def test_invoke_with_unknown_action_after_verification(
    gateway: CredentialGateway,
    tool_server: ToolServer,
) -> None:
    """If the credential matches but the tool doesn't implement the action.

    This shouldn't happen in practice (policy and tool server should
    agree), but the failure mode must be a typed error, not a silent
    success or an AttributeError. The credential layer accepts; the tool
    server raises ``ToolError``.
    """
    # Issue a credential whose tool/action match what the verifier will
    # check, but with an action the tool server has no handler for.
    # Bypass the gateway since policy would reject this — we're testing
    # the tool server's defense-in-depth.
    from nacl.signing import SigningKey

    from aim.audit import InMemoryAuditSink
    from aim.credential import ScopedCredential, sign
    from aim.policy import HardcodedPolicy
    from aim.tool_server import ToolError
    from aim.verifier import Verifier

    key = SigningKey.generate()
    audit = InMemoryAuditSink()
    verifier = Verifier(
        verify_key=key.verify_key,
        audience="tool-server.issues",
        audit=audit,
    )
    server = ToolServer(
        tool="issues",
        verifier=verifier,
        audit=audit,
        _handlers={"list": lambda _args: []},  # no "delete" handler
    )

    cred = ScopedCredential.issue(
        user="u",
        agent="a",
        task="t",
        tool="issues",
        action="delete",  # action the server doesn't implement
        audience="tool-server.issues",
        ttl_seconds=30.0,
    )
    signed = sign(cred, key)

    with pytest.raises(ToolError):
        server.invoke(action="delete", encoded_credential=signed.encode())

    # Verifier accepted; tool_server rejected.
    assert audit.by_kind("verifier.rejected") == []
    invoked = audit.by_kind("tool.invoked")
    assert len(invoked) == 1
    assert invoked[0].outcome == "not_implemented"
    _ = HardcodedPolicy  # silence unused-import lint
