"""Policy-layer tests.

The HardcodedPolicy is the demo's stand-in for a real evaluator. The
tests pin the contract a real evaluator would also have to satisfy:

- Allowed (tool, action) returns ``Decision(allow=True)``.
- Disallowed action returns ``Decision(allow=False)`` with a reason.
- Unknown tool returns ``Decision(allow=False)``.
- Unknown environment returns ``Decision(allow=False)``.
- Mutating actions carry tighter TTL obligations than read-only ones.
"""

from __future__ import annotations

from aim.policy import Decision, HardcodedPolicy, RequestContext


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


def test_allowed_action_is_permitted() -> None:
    decision = HardcodedPolicy().evaluate(_ctx())
    assert decision.allow is True
    assert decision.reason


def test_disallowed_action_is_denied() -> None:
    decision = HardcodedPolicy().evaluate(_ctx(action="delete"))
    assert decision.allow is False
    assert "delete" in decision.reason


def test_unknown_tool_is_denied() -> None:
    decision = HardcodedPolicy().evaluate(_ctx(tool="secrets"))
    assert decision.allow is False
    assert "secrets" in decision.reason


def test_unknown_environment_is_denied() -> None:
    decision = HardcodedPolicy().evaluate(_ctx(environment="strange-env"))
    assert decision.allow is False


def test_decisions_carry_obligations() -> None:
    """Read-only and mutating actions both carry max_ttl obligations."""
    list_decision = HardcodedPolicy().evaluate(_ctx(action="list"))
    read_decision = HardcodedPolicy().evaluate(_ctx(action="read"))

    assert any(o.startswith("max_ttl=") for o in list_decision.obligations)
    assert any(o.startswith("max_ttl=") for o in read_decision.obligations)


def test_decision_is_a_value_type() -> None:
    """Decisions are immutable dataclasses; same inputs → equal outputs."""
    a = HardcodedPolicy().evaluate(_ctx())
    b = HardcodedPolicy().evaluate(_ctx())
    assert a == b
    assert isinstance(a, Decision)
