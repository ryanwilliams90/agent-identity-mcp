"""The demo tool: a tiny in-memory issues store.

Two actions are exposed: ``list`` (return all issues) and ``read``
(return one issue by id). The store is hardcoded; the point of this
module is to be a callable that the tool server invokes after
verification, not to be useful on its own.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Issue:
    issue_id: str
    title: str
    body: str


_FIXTURES: dict[str, Issue] = {
    "ISS-1": Issue("ISS-1", "Investigate flaky deploy", "First seen on Tuesday."),
    "ISS-2": Issue("ISS-2", "Add audit chain to gateway", "Per design note."),
    "ISS-3": Issue("ISS-3", "Document the executor boundary", "Mostly done."),
}


class IssueNotFound(KeyError):
    """Requested issue id is not in the store."""


def list_issues() -> list[Issue]:
    return list(_FIXTURES.values())


def read_issue(issue_id: str) -> Issue:
    try:
        return _FIXTURES[issue_id]
    except KeyError as exc:
        raise IssueNotFound(issue_id) from exc
