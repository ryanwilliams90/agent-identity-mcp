"""Policy evaluation.

The policy evaluator is the seam where "should this action be allowed?"
is decided. Real implementations would back this with OPA, Cedar, or a
custom rule engine; this module provides a Protocol and a hardcoded
implementation that satisfies it.

The Protocol shape is the interesting part: ``evaluate(ctx) -> Decision``
where ``Decision`` carries an explicit ``allow`` flag, a human-readable
reason, and a list of obligations the gateway must enforce on issuance
(e.g., reduced TTL, audit-required, audience restriction). That shape
maps cleanly to OPA's ``allow``/``deny`` decision documents and to
Cedar's policy outcomes, so swapping the backend later is a matter of
substituting the implementation, not rewriting the call sites.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class RequestContext:
    """The full context the policy engine needs to make a decision.

    Every field that could influence authorization is present here. The
    gateway populates this from the incoming request before calling the
    evaluator; the evaluator returns a Decision without further
    side-effects.
    """

    user: str
    agent: str
    task: str
    tool: str
    action: str
    audience: str
    environment: str = "prod"


@dataclass(frozen=True, slots=True)
class Decision:
    """The output of policy evaluation."""

    allow: bool
    reason: str
    obligations: tuple[str, ...] = field(default_factory=tuple)


class PolicyEvaluator(Protocol):
    """The interface the gateway depends on.

    Implementations must be deterministic: the same RequestContext must
    produce the same Decision. (Backends like OPA naturally satisfy this;
    custom evaluators must take care.)
    """

    def evaluate(self, ctx: RequestContext) -> Decision: ...


class HardcodedPolicy:
    """A small, readable policy used by the demo.

    The rules below are illustrative. A real deployment would not encode
    policy in Python — it would version policy as a separate artifact and
    evaluate it via a dedicated engine. The point of this implementation
    is to satisfy the Protocol so the rest of the system is exercisable
    end to end; the *shape* of the interface is what matters.
    """

    # Tools and the actions the policy is willing to issue credentials for.
    # Anything outside this map is denied.
    _ALLOWED_ACTIONS: dict[str, frozenset[str]] = {
        "issues": frozenset({"list", "read"}),
    }

    def evaluate(self, ctx: RequestContext) -> Decision:
        if ctx.environment not in {"prod", "staging", "dev"}:
            return Decision(allow=False, reason=f"unknown environment {ctx.environment!r}")

        allowed = self._ALLOWED_ACTIONS.get(ctx.tool)
        if allowed is None:
            return Decision(allow=False, reason=f"tool {ctx.tool!r} is not registered")

        if ctx.action not in allowed:
            return Decision(
                allow=False,
                reason=f"action {ctx.action!r} not allowed for tool {ctx.tool!r}",
            )

        # Mutating actions get a tighter TTL even when allowed. Read-only
        # actions get a slightly longer one. The gateway is the authority
        # on the actual TTL applied; the obligation is advisory.
        obligations: tuple[str, ...] = ("max_ttl=30",) if ctx.action == "list" else ("max_ttl=10",)

        return Decision(allow=True, reason="permitted by policy", obligations=obligations)
