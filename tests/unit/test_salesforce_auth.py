"""Negative-first tests for EV-42's JWT auth boundary.

These tests exercise our request construction and custody boundary only. They
do not replace the required live Salesforce integration tests.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from services.connectors.salesforce import (
    CredentialKeyCustody,
    HostedCredentialCustodyError,
    SalesforceJwtBearerAuth,
    SalesforceJwtBearerConfig,
)


def _decode_segment(segment: str) -> object:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


@dataclass(frozen=True)
class _RecordingSigner:
    custody: CredentialKeyCustody = CredentialKeyCustody.CLIENT_HELD
    key_reference: str = "customer-signer://salesforce/probe"
    signed: list[bytes] | None = None

    def sign_rs256(self, message: bytes) -> bytes:
        if self.signed is not None:
            self.signed.append(message)
        return b"signature-from-injected-provider"


def _config() -> SalesforceJwtBearerConfig:
    return SalesforceJwtBearerConfig(
        client_id="external-client-app-consumer-key",
        subject="agent.integration@example.test",
        audience="https://login.salesforce.com",
        assertion_lifetime=timedelta(minutes=2),
    )


def test_hosted_key_custody_is_refused_without_explicit_opt_in() -> None:
    signer = _RecordingSigner(custody=CredentialKeyCustody.HOSTED_KMS)

    with pytest.raises(HostedCredentialCustodyError, match="explicit opt-in"):
        SalesforceJwtBearerAuth(config=_config(), signer=signer)


def test_jwt_request_uses_injected_client_held_signer_and_no_private_key() -> None:
    signed: list[bytes] = []
    auth = SalesforceJwtBearerAuth(
        config=_config(),
        signer=_RecordingSigner(signed=signed),
    )
    now = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)

    request = auth.build_token_request(now=now, nonce="one-use-id")

    assert request.url == "https://login.salesforce.com/services/oauth2/token"
    assert request.headers == {"Content-Type": "application/x-www-form-urlencoded"}
    assert request.form["grant_type"] == (
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    )
    assertion = request.form["assertion"]
    header_segment, claims_segment, _signature_segment = assertion.split(".")
    assert _decode_segment(header_segment) == {"alg": "RS256", "typ": "JWT"}
    assert _decode_segment(claims_segment) == {
        "aud": "https://login.salesforce.com",
        "exp": 1_787_054_520,
        "iss": "external-client-app-consumer-key",
        "jti": "one-use-id",
        "sub": "agent.integration@example.test",
    }
    assert signed == [f"{header_segment}.{claims_segment}".encode("ascii")]
    assert auth.credential_custody is CredentialKeyCustody.CLIENT_HELD
    assert not hasattr(auth, "private_key")
    assert not hasattr(auth.config, "private_key")


def test_jwt_auth_rejects_non_https_authorization_server() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        SalesforceJwtBearerConfig(
            client_id="client",
            subject="agent@example.test",
            audience="http://login.salesforce.com",
        )


@pytest.mark.parametrize(
    "lifetime",
    [timedelta(0), timedelta(seconds=-1), timedelta(minutes=3, seconds=1)],
)
def test_jwt_auth_rejects_unsafe_assertion_lifetimes(lifetime: timedelta) -> None:
    with pytest.raises(ValueError, match="assertion_lifetime"):
        SalesforceJwtBearerConfig(
            client_id="client",
            subject="agent@example.test",
            audience="https://login.salesforce.com",
            assertion_lifetime=lifetime,
        )
