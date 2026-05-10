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
    already emitted an audit record before raising.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# Default ceiling — credentials cannot be issued for longer than this
# regardless of what an obligation asks for. The point is to bound the
# blast radius of a leak even if a policy bug grants too generously.
_DEFAULT_TTL_CEILING_SECONDS = 60.0
_MAX_TTL_PATTERN = re.compile(r"^max_ttl=(\d+(?:\.\d+)?)$")


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

        Raises ``IssuanceDenied`` on policy denial. An audit record is
        emitted for both outcomes — denials are part of the trust chain
        and have to be explainable later.
        """
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
                    reason=decision.reason,
                    outcome="denied",
                )
            )
            raise IssuanceDenied(decision.reason)

        ttl = self._resolve_ttl(decision)
        credential = ScopedCredential.issue(
            user=ctx.user,
            agent=ctx.agent,
            task=ctx.task,
            tool=ctx.tool,
            action=ctx.action,
            audience=ctx.audience,
            ttl_seconds=ttl,
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
                reason=decision.reason,
                outcome="issued",
            )
        )
        return signed

    def _resolve_ttl(self, decision: Decision) -> float:
        """Take the smallest of: ceiling, any max_ttl obligation."""
        ttl = self.ttl_ceiling_seconds
        for obligation in decision.obligations:
            match = _MAX_TTL_PATTERN.match(obligation)
            if match is None:
                continue
            requested = float(match.group(1))
            if requested < ttl:
                ttl = requested
        return ttl
