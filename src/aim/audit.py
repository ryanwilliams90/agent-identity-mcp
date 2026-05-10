"""Structured audit records.

Audit is a primary output of the system, not a side effect. Every event
that affects the trust chain — credential issuance, policy denial,
verifier rejection, tool execution — produces a record. The records are
structured so a downstream consumer can answer "why did agent A take
action B on behalf of user C, under what authority, and what happened?"
without reconstructing intent from free-form logs.

This implementation keeps records in memory because the prototype's job
is to demonstrate the shape, not to be a durable audit store. Real
deployments would write to an append-only sink with cryptographic
chaining; the ``AuditSink`` Protocol below is what such a backend would
implement.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Literal, Protocol

EventKind = Literal[
    "credential.issued",
    "policy.denied",
    "verifier.rejected",
    "tool.invoked",
    "tool.completed",
]


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A single audit record.

    Fields are populated to whatever degree is meaningful for the kind of
    event. ``credential_id`` is set whenever a credential exists in the
    chain (issuance, verification, tool invocation). ``reason`` carries
    the policy decision text or the verifier's rejection reason.
    """

    event_id: str
    kind: EventKind
    timestamp: float
    user: str
    agent: str
    task: str
    tool: str
    action: str
    credential_id: str | None = None
    reason: str | None = None
    outcome: str | None = None


class AuditSink(Protocol):
    """The interface the gateway and verifier write through.

    Real backends would implement this with appending writes to a durable
    store, optional Merkle chaining for tamper-evidence, and forwarding
    to the org's SIEM. This Protocol exists so that wiring is consistent
    even when the backend changes.
    """

    def emit(self, event: AuditEvent) -> None: ...


@dataclass(slots=True)
class InMemoryAuditSink:
    """Reference implementation. Holds events in a list."""

    events: list[AuditEvent] = field(default_factory=list)

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)

    def by_kind(self, kind: EventKind) -> list[AuditEvent]:
        return [e for e in self.events if e.kind == kind]


def make_event(
    kind: EventKind,
    *,
    user: str,
    agent: str,
    task: str,
    tool: str,
    action: str,
    credential_id: str | None = None,
    reason: str | None = None,
    outcome: str | None = None,
    now: float | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        kind=kind,
        timestamp=time.time() if now is None else now,
        user=user,
        agent=agent,
        task=task,
        tool=tool,
        action=action,
        credential_id=credential_id,
        reason=reason,
        outcome=outcome,
    )
