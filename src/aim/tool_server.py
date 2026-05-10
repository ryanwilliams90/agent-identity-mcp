"""The tool server.

An MCP-style server that exposes one or more actions on a tool. The
critical structural property: tool code is never invoked unless the
verifier has accepted the credential for *the action being requested*.
The verification step is not a polite request — the tool server's
``invoke`` method has no path that reaches a tool handler without
calling ``Verifier.verify`` first.

A buggy or compromised tool server that tried to skip verification
would have to do so by editing this module. The architectural claim is
that legitimate tool servers don't accidentally bypass verification
because the structure doesn't admit a path that does.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from aim.audit import AuditSink, make_event
from aim.tools.issues import IssueNotFound, list_issues, read_issue
from aim.verifier import VerificationFailed, Verifier


class ToolError(Exception):
    """Tool execution failed for non-authorization reasons (e.g., not found)."""


# A tool handler takes the verified credential and the request arguments
# and returns the tool's result. Handlers never run unless the verifier
# has accepted the credential first — that constraint is enforced by
# the only call site in this module, ``ToolServer.invoke``.
ToolHandler = Callable[[dict[str, Any]], Any]


@dataclass(slots=True)
class ToolServer:
    """An MCP-style server exposing a single tool's actions."""

    tool: str
    verifier: Verifier
    audit: AuditSink
    _handlers: dict[str, ToolHandler]

    @classmethod
    def for_issues(cls, *, verifier: Verifier, audit: AuditSink) -> ToolServer:
        """Construct a server exposing the issues tool's actions."""
        handlers: dict[str, ToolHandler] = {
            "list": _handle_list,
            "read": _handle_read,
        }
        return cls(tool="issues", verifier=verifier, audit=audit, _handlers=handlers)

    def invoke(
        self,
        *,
        action: str,
        encoded_credential: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """Verify, then run the tool handler.

        Verification happens first, unconditionally. Any
        ``VerificationFailed`` propagates to the caller — the tool
        handler is not reached. This is the structural guarantee the
        prototype demonstrates.
        """
        # The verifier raises on failure; we let it propagate. The
        # rejection has already been audited inside the verifier.
        credential = self.verifier.verify(
            encoded_credential,
            requested_action=action,
            requested_tool=self.tool,
        )

        handler = self._handlers.get(action)
        if handler is None:
            # Reachable only if the verifier accepted an action we don't
            # know how to execute — which means policy and the tool
            # server disagree about the action surface. Audit and raise.
            self.audit.emit(
                make_event(
                    "tool.invoked",
                    user=credential.user,
                    agent=credential.agent,
                    task=credential.task,
                    tool=self.tool,
                    action=action,
                    credential_id=credential.credential_id,
                    reason="action verified by policy but not implemented by tool server",
                    outcome="not_implemented",
                )
            )
            raise ToolError(f"action {action!r} is not implemented on tool {self.tool!r}")

        self.audit.emit(
            make_event(
                "tool.invoked",
                user=credential.user,
                agent=credential.agent,
                task=credential.task,
                tool=self.tool,
                action=action,
                credential_id=credential.credential_id,
                outcome="invoked",
            )
        )

        result = handler(arguments or {})

        self.audit.emit(
            make_event(
                "tool.completed",
                user=credential.user,
                agent=credential.agent,
                task=credential.task,
                tool=self.tool,
                action=action,
                credential_id=credential.credential_id,
                outcome="ok",
            )
        )
        return result


def _handle_list(_: dict[str, Any]) -> list[dict[str, str]]:
    return [{"issue_id": issue.issue_id, "title": issue.title} for issue in list_issues()]


def _handle_read(arguments: dict[str, Any]) -> dict[str, str]:
    issue_id = arguments.get("issue_id")
    if not isinstance(issue_id, str):
        raise ToolError("'issue_id' is required and must be a string")
    try:
        issue = read_issue(issue_id)
    except IssueNotFound as exc:
        raise ToolError(f"issue {issue_id!r} not found") from exc
    return {"issue_id": issue.issue_id, "title": issue.title, "body": issue.body}


# Re-export VerificationFailed so callers can import the rejection types
# from the tool_server module without reaching across the boundary into
# verifier internals.
__all__ = ["ToolError", "ToolServer", "VerificationFailed"]
