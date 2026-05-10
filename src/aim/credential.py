"""Scoped credentials.

A credential carries the full context an action was authorized for —
user, agent, task, tool, action, audience, expiry, and a nonce — signed
by the issuer. Verification is asymmetric: the gateway holds the signing
key, any tool server can verify with the public key, and there is no
shared secret.

The credential is the unit the verifier checks. Every property the
verifier rejects on (audience, action, expiry, signature, replay) is
encoded here. The verifier itself lives in ``verifier`` because
cryptographic verification and replay state belong on the consumer side,
not on the credential value type.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


class CredentialError(Exception):
    """Base class for credential-layer errors."""


class InvalidSignature(CredentialError):
    """The signature does not match the credential body or signing key."""


class MalformedCredential(CredentialError):
    """The encoded credential could not be parsed."""


@dataclass(frozen=True, slots=True)
class ScopedCredential:
    """A capability to perform a specific action, bound to a specific actor.

    All five identity facets are part of the signed payload, so a verifier
    that checks signature + audience + action + expiry + nonce has, by
    construction, also checked who the credential was issued to and what
    task it was issued for.
    """

    credential_id: str
    user: str
    agent: str
    task: str
    tool: str
    action: str
    audience: str
    issued_at: float
    expires_at: float
    nonce: str

    def to_payload(self) -> dict[str, Any]:
        """Return the canonical dict representation that gets signed."""
        return asdict(self)

    @classmethod
    def issue(
        cls,
        *,
        user: str,
        agent: str,
        task: str,
        tool: str,
        action: str,
        audience: str,
        ttl_seconds: float,
        now: float | None = None,
    ) -> ScopedCredential:
        """Construct a credential with a fresh id and nonce.

        ``ttl_seconds`` is bounded by the caller (the gateway). This
        constructor does not enforce a ceiling — the policy evaluator and
        gateway are the right place for that decision.
        """
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        t = time.time() if now is None else now
        return cls(
            credential_id=str(uuid.uuid4()),
            user=user,
            agent=agent,
            task=task,
            tool=tool,
            action=action,
            audience=audience,
            issued_at=t,
            expires_at=t + ttl_seconds,
            nonce=secrets.token_hex(16),
        )


@dataclass(frozen=True, slots=True)
class SignedCredential:
    """A credential plus its detached signature.

    The wire format is opaque to consumers — they receive a single
    ``encoded`` string from the gateway and pass it to the verifier. The
    structure (payload + signature) is internal and serialized via
    ``encode``/``decode``.
    """

    credential: ScopedCredential
    signature: bytes

    def encode(self) -> str:
        """Serialize to a single transmissible string.

        Format: base64url(json(payload)) + "." + base64url(signature).
        Mirrors the JWT shape so the structure is familiar; nothing in the
        verifier depends on it being JWT-compatible.
        """
        payload_json = json.dumps(self.credential.to_payload(), sort_keys=True)
        payload_b64 = _b64url_encode(payload_json.encode("utf-8"))
        sig_b64 = _b64url_encode(self.signature)
        return f"{payload_b64}.{sig_b64}"


def sign(credential: ScopedCredential, signing_key: SigningKey) -> SignedCredential:
    """Sign a credential with the issuer's private key.

    The signed bytes are the canonical JSON of the payload — sorted keys
    so the same credential always produces the same signature input.
    """
    payload_bytes = _payload_bytes(credential)
    signed = signing_key.sign(payload_bytes)
    return SignedCredential(credential=credential, signature=signed.signature)


def verify_signature(encoded: str, verify_key: VerifyKey) -> ScopedCredential:
    """Verify the signature on an encoded credential and return the body.

    Raises:
        MalformedCredential: the encoded form could not be parsed.
        InvalidSignature: the signature did not match the verifier's key.

    Audience, action, expiry, and replay are checked elsewhere — by
    design, this function is responsible only for "did the issuer sign
    this body, unmodified, with the key we trust?".
    """
    try:
        payload_b64, sig_b64 = encoded.split(".", 1)
    except ValueError as exc:
        raise MalformedCredential("expected two base64url segments separated by '.'") from exc

    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
    except (ValueError, TypeError) as exc:
        raise MalformedCredential("base64url decode failed") from exc

    try:
        verify_key.verify(payload_bytes, signature)
    except BadSignatureError as exc:
        raise InvalidSignature("signature does not match verifier key") from exc

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedCredential("payload is not valid utf-8 JSON") from exc

    try:
        return ScopedCredential(**payload)
    except TypeError as exc:
        raise MalformedCredential(f"payload missing required fields: {exc}") from exc


def _payload_bytes(credential: ScopedCredential) -> bytes:
    return json.dumps(credential.to_payload(), sort_keys=True).encode("utf-8")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
