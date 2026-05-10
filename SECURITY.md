# Security

These repositories are reference implementations and architecture artifacts, not production security products.

The code in this repo demonstrates a design — gateway-mediated scoped credential issuance with verifier-side authorization for agent tool calls. It is not intended to be used as-is for production authorization, credential issuance, secret management, or runtime enforcement. Real deployments need durable replay state, key rotation, revocation, hardened key storage, and an audit sink with appropriate guarantees, none of which are implemented here.

If you find a security issue in the demonstration code itself — a verification bypass, a signature handling bug, a logic flaw in the threat-model checks the prototype claims to enforce — please report it privately to ryan90@gmail.com. Public issues for security flaws will be redirected.

## Scope

In scope for security reports:

- Verification bypasses in `Verifier.verify` (signature, audience, action, expiry, replay).
- Tool server paths that reach a tool handler without the verifier's check.
- Credential mutability after signing.
- Audit records that misrepresent what happened.

Out of scope:

- The in-memory replay cache (documented as not durable).
- The hardcoded policy (documented as a Protocol stand-in).
- Missing production features (revocation, key rotation, delegation chains, durable audit).

These are listed in the README's "What this is not" section as deliberate limitations of a demonstration prototype.
