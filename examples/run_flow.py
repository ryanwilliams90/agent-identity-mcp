"""Programmatic demo of the threat-model scenario.

Runs the full happy path, then demonstrates the headline rejection: a
credential issued for ``list`` cannot be used to call ``read``. The
verifier rejects before any tool code runs, and the audit chain shows
the rejection without a corresponding ``tool.invoked`` event.

Run:

    python examples/run_flow.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make ``aim`` importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nacl.signing import SigningKey  # noqa: E402

from aim.audit import InMemoryAuditSink  # noqa: E402
from aim.gateway import CredentialGateway  # noqa: E402
from aim.policy import HardcodedPolicy, RequestContext  # noqa: E402
from aim.tool_server import ToolServer  # noqa: E402
from aim.verifier import ActionMismatch, Verifier  # noqa: E402


def main() -> None:
    audit = InMemoryAuditSink()
    signing_key = SigningKey.generate()

    gateway = CredentialGateway(
        signing_key=signing_key,
        policy=HardcodedPolicy(),
        audit=audit,
    )
    verifier = Verifier(
        verify_key=gateway.verify_key,
        audience="tool-server.issues",
        audit=audit,
    )
    tool_server = ToolServer.for_issues(verifier=verifier, audit=audit)

    base_ctx = RequestContext(
        user="alice@example.com",
        agent="agent-runtime-A",
        task="summarize-open-issues",
        tool="issues",
        action="list",
        audience="tool-server.issues",
    )

    print("=== happy path: agent calls list with a list-scoped credential ===")
    signed_list = gateway.issue(base_ctx)
    result = tool_server.invoke(action="list", encoded_credential=signed_list.encode())
    print(f"tool returned {len(result)} issues")
    print()

    print("=== escalation attempt: agent presents the list credential to call read ===")
    print("(this is the threat model — buggy/compromised path tries to use a")
    print(" credential beyond its issued action; verifier rejects before tool runs)")
    signed_for_list_again = gateway.issue(base_ctx)
    try:
        tool_server.invoke(
            action="read",  # different action from what the credential authorizes
            encoded_credential=signed_for_list_again.encode(),
            arguments={"issue_id": "ISS-1"},
        )
    except ActionMismatch as exc:
        print(f"rejected: {exc}")
    print()

    print("=== audit chain ===")
    print("(invocation_id ties events from one agent action together)")
    for event in audit.events:
        record = {
            "kind": event.kind,
            "invocation_id": (
                event.invocation_id[:8] + "..." if event.invocation_id else None
            ),
            "user": event.user,
            "tool": event.tool,
            "action": event.action,
            "outcome": event.outcome,
        }
        if event.reason:
            record["reason"] = event.reason
        print(json.dumps(record))


if __name__ == "__main__":
    main()
