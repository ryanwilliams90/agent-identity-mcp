"""Agent identity / MCP credential plane — reference implementation.

A small, working demonstration of gateway-mediated scoped credential
issuance for agent runtimes calling MCP-style tools. The architectural
claim is that authorization happens at *call time*, not at install
time; that credentials are issued per action and never enter the model
context as raw secrets; and that verification runs *outside* tool code
so a buggy or compromised tool server cannot bypass scope enforcement.

This is a reference implementation, not production infrastructure. See
the README for the design claim it demonstrates and the boundaries of
what it sets out to do.
"""

from aim.audit import AuditEvent, AuditSink, InMemoryAuditSink, make_event
from aim.credential import (
    InvalidSignature,
    MalformedCredential,
    ScopedCredential,
    SignedCredential,
    sign,
    verify_signature,
)
from aim.gateway import CredentialGateway, IssuanceDenied
from aim.policy import Decision, HardcodedPolicy, PolicyEvaluator, RequestContext
from aim.tool_server import ToolError, ToolServer
from aim.verifier import (
    ActionMismatch,
    AudienceMismatch,
    BadCredential,
    CredentialExpired,
    CredentialReplayed,
    VerificationFailed,
    Verifier,
)

__all__ = [
    "ActionMismatch",
    "AudienceMismatch",
    "AuditEvent",
    "AuditSink",
    "BadCredential",
    "CredentialExpired",
    "CredentialGateway",
    "CredentialReplayed",
    "Decision",
    "HardcodedPolicy",
    "InMemoryAuditSink",
    "InvalidSignature",
    "IssuanceDenied",
    "MalformedCredential",
    "PolicyEvaluator",
    "RequestContext",
    "ScopedCredential",
    "SignedCredential",
    "ToolError",
    "ToolServer",
    "VerificationFailed",
    "Verifier",
    "make_event",
    "sign",
    "verify_signature",
]
