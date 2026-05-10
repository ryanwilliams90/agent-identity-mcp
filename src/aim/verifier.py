"""The verifier.

This module is the architectural reason a compromised or buggy tool
server cannot bypass scope enforcement. The verifier runs *before* tool
code executes, takes a credential and the request the tool server was
asked to handle, and answers a single question: is this credential
valid for *this exact action*?

The threat model the prototype demonstrates: a buggy or compromised
agent/tool path attempts to use a credential issued for action A to
perform action B. The verifier rejects before tool execution. The tool
code is structurally never reached on a rejected call — the tool server
must call ``Verifier.verify`` first, and a thrown ``VerificationFailed``
returns the request to the caller without invoking the tool.

The verifier holds:
- the issuer's public key (to check signatures)
- the audience this verifier represents (to reject misrouted credentials)
- a replay cache (to reject reused nonces)

Five rejection reasons, each a distinct subclass so audit records and
tests can tell them apart:
- bad signature (or malformed credential)
- audience mismatch
- action mismatch
- expired
- replayed
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from nacl.signing import VerifyKey

from aim.audit import AuditSink, make_event
from aim.credential import (
    InvalidSignature,
    MalformedCredential,
    ScopedCredential,
    verify_signature,
)


class VerificationFailed(Exception):
    """Base class for verifier rejections."""

    code: str = "verification_failed"


class BadCredential(VerificationFailed):
    """Signature did not verify, or the encoded form was malformed."""

    code = "bad_credential"


class AudienceMismatch(VerificationFailed):
    """Credential was minted for a different tool server."""

    code = "audience_mismatch"


class ActionMismatch(VerificationFailed):
    """Credential was issued for a different action than the one requested.

    This is the rejection at the heart of the prototype's demonstration:
    a credential issued for ``list`` cannot be used to call ``read``,
    even though both are actions on the same tool.
    """

    code = "action_mismatch"


class CredentialExpired(VerificationFailed):
    """The credential's expiry has passed."""

    code = "expired"


class CredentialReplayed(VerificationFailed):
    """The credential's nonce has already been seen by this verifier."""

    code = "replayed"


@dataclass(slots=True)
class Verifier:
    """Scope-enforcing verifier for a tool server.

    The verifier is constructed with the issuer's public key and the
    audience identifier this tool server claims. ``verify`` is called by
    the tool server before any tool code runs, and either returns the
    decoded ``ScopedCredential`` (verification passed) or raises a
    ``VerificationFailed`` subclass.

    Replay protection caveats this prototype does not address:

    - The ``_seen_nonces`` set grows without bound. A real verifier would
      evict nonces whose credentials have expired (since expired
      credentials are rejected anyway, retaining their nonces serves no
      purpose) and back the set with a shared store so multiple verifier
      processes share replay state.
    - The check-then-add (``in`` then ``add``) is not atomic. CPython's
      GIL makes a single set operation atomic, not the pair; two
      verifier instances on the same nonce could both succeed under
      racing concurrent calls. A production implementation needs an
      atomic compare-and-set against the shared store.

    Both are intentionally out of scope; the prototype demonstrates the
    rejection property, not durable replay state.
    """

    verify_key: VerifyKey
    audience: str
    audit: AuditSink
    _seen_nonces: set[str] = field(default_factory=set, init=False)

    def verify(
        self,
        encoded_credential: str,
        *,
        requested_action: str,
        requested_tool: str,
    ) -> ScopedCredential:
        """Verify a credential against a specific tool/action request.

        Raises a ``VerificationFailed`` subclass on any check failure.
        Each failure path emits an audit record before raising so the
        rejection is explainable downstream.
        """
        try:
            credential = verify_signature(encoded_credential, self.verify_key)
        except (InvalidSignature, MalformedCredential) as exc:
            # No identity context to attribute — the credential body
            # cannot be trusted. Audit with sentinel values.
            self._audit_rejection(
                credential=None,
                requested_tool=requested_tool,
                requested_action=requested_action,
                code=BadCredential.code,
                reason=str(exc),
            )
            raise BadCredential(str(exc)) from exc

        if credential.audience != self.audience:
            self._audit_rejection(
                credential=credential,
                requested_tool=requested_tool,
                requested_action=requested_action,
                code=AudienceMismatch.code,
                reason=(
                    f"credential audience {credential.audience!r} "
                    f"does not match verifier audience {self.audience!r}"
                ),
            )
            raise AudienceMismatch(
                f"credential audience {credential.audience!r} "
                f"does not match verifier {self.audience!r}"
            )

        if credential.tool != requested_tool or credential.action != requested_action:
            reason = (
                f"credential is for {credential.tool}.{credential.action}, "
                f"request is for {requested_tool}.{requested_action}"
            )
            self._audit_rejection(
                credential=credential,
                requested_tool=requested_tool,
                requested_action=requested_action,
                code=ActionMismatch.code,
                reason=reason,
            )
            raise ActionMismatch(reason)

        if credential.expires_at <= time.time():
            self._audit_rejection(
                credential=credential,
                requested_tool=requested_tool,
                requested_action=requested_action,
                code=CredentialExpired.code,
                reason=f"credential expired at {credential.expires_at}",
            )
            raise CredentialExpired(f"credential expired at {credential.expires_at}")

        if credential.nonce in self._seen_nonces:
            self._audit_rejection(
                credential=credential,
                requested_tool=requested_tool,
                requested_action=requested_action,
                code=CredentialReplayed.code,
                reason=f"nonce {credential.nonce} already seen",
            )
            raise CredentialReplayed(f"nonce {credential.nonce} already seen")

        self._seen_nonces.add(credential.nonce)
        return credential

    def _audit_rejection(
        self,
        *,
        credential: ScopedCredential | None,
        requested_tool: str,
        requested_action: str,
        code: str,
        reason: str,
    ) -> None:
        self.audit.emit(
            make_event(
                "verifier.rejected",
                user=credential.user if credential else "<unknown>",
                agent=credential.agent if credential else "<unknown>",
                task=credential.task if credential else "<unknown>",
                tool=requested_tool,
                action=requested_action,
                credential_id=credential.credential_id if credential else None,
                invocation_id=credential.invocation_id if credential else None,
                reason=reason,
                outcome=code,
            )
        )
