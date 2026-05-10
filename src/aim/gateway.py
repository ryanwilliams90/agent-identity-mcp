"""The credential gateway.

The gateway is the single point at which credentials are minted. It
takes a request context, consults the policy evaluator, applies TTL
obligations, signs a scoped credential with its private key, and emits
an audit record. Agents never see the gateway's signing key; tool
servers never see anything but the verify key.

This is the layer the case study calls the *enforcement point*. It is
where "is this action allowed, right now, in this context?" is answered.
Putting the decision here — and not at integration time, not in the
agent runtime, not in the IDE — is the core architectural claim.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from nacl.signing import SigningKey, VerifyKey

from aim.audit import AuditSink, make_event
from aim.credential import ScopedCredential, SignedCredential, sign
from aim.policy import Decision, PolicyEvaluator, RequestContext


class GatewayError(Exception):
    """Base class for gateway-layer errors."""


class IssuanceDenied(GatewayError):
    """The policy evaluator denied the request.

    The denial reason is preserved for the caller; the gateway has
    already emitted an audit record before raising. Raised both for
    explicit policy denial and for issuance refused due to a malformed
    policy obligation — the gateway will not mint a credential off a
    policy decision it cannot fully honor.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# Default ceiling — credentials cannot be issued for longer than this
# regardless of what an obligation asks for. The point is to bound the
# blast radius of a leak even if a policy bug grants too generously.
_DEFAULT_TTL_CEILING_SECONDS = 60.0
# Match any ``max_ttl=<float>`` shape, including signed and zero. Range
# checks happen after the parse so malformed values produce clean errors
# rather than silent regex non-matches.
_MAX_TTL_PATTERN = re.compile(r"^max_ttl=(-?\d+(?:\.\d+)?)$")


@dataclass(slots=True)
class CredentialGateway:
    """Issues scoped credentials. The architectural enforcement point."""

    signing_key: SigningKey
    policy: PolicyEvaluator
    audit: AuditSink
    ttl_ceiling_seconds: float = _DEFAULT_TTL_CEILING_SECONDS

    @property
    def verify_key(self) -> VerifyKey:
        """The public key tool-server verifiers use to check signatures."""
        return self.signing_key.verify_key

    def issue(self, ctx: RequestContext) -> SignedCredential:
        """Evaluate policy and, if allowed, mint and sign a credential.

        Raises ``IssuanceDenied`` on policy denial or on a malformed
        policy obligation the gateway cannot honor. An audit record is
        emitted for both outcomes — denials are part of the trust chain
        and have to be explainable later.

        A fresh ``invocation_id`` is generated per call and threaded
        through the audit chain (issuance, verification, execution) so a
        downstream consumer can join the events for a single agent
        action without timestamp ordering.
        """
        invocation_id = str(uuid.uuid4())

        decision = self.policy.evaluate(ctx)
        if not decision.allow:
            self.audit.emit(
                make_event(
                    "policy.denied",
                    user=ctx.user,
                    agent=ctx.agent,
                    task=ctx.task,
                    tool=ctx.tool,
                    action=ctx.action,
                    invocation_id=invocation_id,
                    reason=decision.reason,
                    outcome="denied",
                )
            )
            raise IssuanceDenied(decision.reason)

        try:
            ttl = self._resolve_ttl(decision)
        except _MalformedObligation as exc:
            # Defense in depth: a buggy or malicious policy that emits a
            # malformed ``max_ttl`` obligation is treated as a denial,
            # not silently dropped. The audit reason names the bad
            # obligation so the policy author can find it.
            reason = f"malformed policy obligation: {exc}"
            self.audit.emit(
                make_event(
                    "policy.denied",
                    user=ctx.user,
                    agent=ctx.agent,
                    task=ctx.task,
                    tool=ctx.tool,
                    action=ctx.action,
                    invocation_id=invocation_id,
                    reason=reason,
                    outcome="denied",
                )
            )
            raise IssuanceDenied(reason) from exc

        credential = ScopedCredential.issue(
            user=ctx.user,
            agent=ctx.agent,
            task=ctx.task,
            tool=ctx.tool,
            action=ctx.action,
            audience=ctx.audience,
            ttl_seconds=ttl,
            invocation_id=invocation_id,
        )
        signed = sign(credential, self.signing_key)

        self.audit.emit(
            make_event(
                "credential.issued",
                user=ctx.user,
                agent=ctx.agent,
                task=ctx.task,
                tool=ctx.tool,
                action=ctx.action,
                credential_id=credential.credential_id,
                invocation_id=invocation_id,
                reason=decision.reason,
                outcome="issued",
            )
        )
        return signed

    def _resolve_ttl(self, decision: Decision) -> float:
        """Take the smallest of: ceiling, any max_ttl obligation.

        Raises ``_MalformedObligation`` if a ``max_ttl=...`` obligation
        parses but is non-positive — the gateway will not honor a
        decision that asks for a zero-or-negative TTL. Obligations whose
        prefix is not ``max_ttl=`` are ignored as forward compatibility
        for directives the gateway doesn't recognize.
        """
        ttl = self.ttl_ceiling_seconds
        for obligation in decision.obligations:
            if not obligation.startswith("max_ttl="):
                continue
            match = _MAX_TTL_PATTERN.match(obligation)
            if match is None:
                raise _MalformedObligation(f"max_ttl obligation {obligation!r} could not be parsed")
            requested = float(match.group(1))
            if requested <= 0:
                raise _MalformedObligation(f"max_ttl obligation {obligation!r} must be positive")
            if requested < ttl:
                ttl = requested
        return ttl


class _MalformedObligation(Exception):
    """Internal — converted to ``IssuanceDenied`` in ``issue``."""
