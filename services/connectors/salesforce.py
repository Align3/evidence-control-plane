"""Salesforce connector authentication boundary for EV-42.

The RSA key is deliberately absent from this module.  A deployment supplies a
signing capability, which can be backed by a customer-held remote signer or by
an explicitly opted-in hosted KMS.  This keeps private-key generation,
serialization, persistence, and secret loading outside the connector.

This module currently stops at constructing the OAuth token request.  Sending
that request and using its token for Salesforce REST/SOQL calls begins only
when the live External Client App configuration is available.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlsplit

_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_MAX_ASSERTION_LIFETIME = timedelta(minutes=3)


class CredentialKeyCustody(StrEnum):
    """Custody of the RSA key used to authenticate to Salesforce."""

    CLIENT_HELD = "client_held"
    HOSTED_KMS = "hosted_kms"


class HostedCredentialCustodyError(ValueError):
    """Hosted key use was attempted without an explicit deployment opt-in."""


class JwtRs256Signer(Protocol):
    """Opaque RS256 signing capability; raw key bytes never cross this API."""

    @property
    def custody(self) -> CredentialKeyCustody: ...

    @property
    def key_reference(self) -> str: ...

    def sign_rs256(self, message: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SalesforceJwtBearerConfig:
    """Non-secret External Client App values needed for JWT bearer auth."""

    client_id: str
    subject: str
    audience: str
    assertion_lifetime: timedelta = timedelta(minutes=2)

    def __post_init__(self) -> None:
        if not self.client_id:
            raise ValueError("client_id is required")
        if not self.subject:
            raise ValueError("subject is required")
        parsed = urlsplit(self.audience)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("audience must be an HTTPS Salesforce authorization URL")
        if not timedelta(0) < self.assertion_lifetime <= _MAX_ASSERTION_LIFETIME:
            raise ValueError("assertion_lifetime must be greater than zero and at most 3 minutes")

    @property
    def token_endpoint(self) -> str:
        return self.audience.rstrip("/") + "/services/oauth2/token"


@dataclass(frozen=True, slots=True)
class SalesforceTokenRequest:
    """A fully formed token exchange request, not a transmitted credential."""

    url: str
    headers: Mapping[str, str]
    form: Mapping[str, str]
    key_reference: str
    credential_custody: CredentialKeyCustody


@dataclass(frozen=True, slots=True)
class SalesforceJwtBearerAuth:
    """Construct JWT bearer token requests using an injected opaque signer."""

    config: SalesforceJwtBearerConfig
    signer: JwtRs256Signer
    allow_hosted_key_custody: bool = False

    def __post_init__(self) -> None:
        if not self.signer.key_reference:
            raise ValueError("signer key_reference is required")
        if (
            self.signer.custody is CredentialKeyCustody.HOSTED_KMS
            and not self.allow_hosted_key_custody
        ):
            raise HostedCredentialCustodyError(
                "hosted KMS credential custody requires explicit opt-in and disclosure"
            )

    @property
    def credential_custody(self) -> CredentialKeyCustody:
        return self.signer.custody

    def build_token_request(
        self,
        *,
        now: datetime | None = None,
        nonce: str | None = None,
    ) -> SalesforceTokenRequest:
        """Build one non-replayable Salesforce JWT bearer token request."""

        issued_at = now or datetime.now(UTC)
        if issued_at.tzinfo is None or issued_at.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        assertion_id = nonce or secrets.token_urlsafe(24)
        if not assertion_id:
            raise ValueError("nonce must not be empty")
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "aud": self.config.audience,
            "exp": int((issued_at + self.config.assertion_lifetime).timestamp()),
            "iss": self.config.client_id,
            "jti": assertion_id,
            "sub": self.config.subject,
        }
        header_segment = _base64url_json(header)
        claims_segment = _base64url_json(claims)
        signing_input = f"{header_segment}.{claims_segment}".encode("ascii")
        signature_segment = _base64url(self.signer.sign_rs256(signing_input))
        assertion = f"{header_segment}.{claims_segment}.{signature_segment}"
        return SalesforceTokenRequest(
            url=self.config.token_endpoint,
            headers=MappingProxyType(
                {"Content-Type": "application/x-www-form-urlencoded"}
            ),
            form=MappingProxyType(
                {"grant_type": _JWT_BEARER_GRANT, "assertion": assertion}
            ),
            key_reference=self.signer.key_reference,
            credential_custody=self.signer.custody,
        )


def _base64url_json(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return _base64url(encoded)


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
