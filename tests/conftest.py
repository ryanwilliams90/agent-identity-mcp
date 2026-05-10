"""Shared fixtures for the test suite."""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from aim.audit import InMemoryAuditSink
from aim.gateway import CredentialGateway
from aim.policy import HardcodedPolicy
from aim.tool_server import ToolServer
from aim.verifier import Verifier


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def audit() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture
def gateway(signing_key: SigningKey, audit: InMemoryAuditSink) -> CredentialGateway:
    return CredentialGateway(
        signing_key=signing_key,
        policy=HardcodedPolicy(),
        audit=audit,
    )


@pytest.fixture
def issues_audience() -> str:
    return "tool-server.issues"


@pytest.fixture
def verifier(
    signing_key: SigningKey,
    audit: InMemoryAuditSink,
    issues_audience: str,
) -> Verifier:
    return Verifier(
        verify_key=signing_key.verify_key,
        audience=issues_audience,
        audit=audit,
    )


@pytest.fixture
def tool_server(verifier: Verifier, audit: InMemoryAuditSink) -> ToolServer:
    return ToolServer.for_issues(verifier=verifier, audit=audit)
