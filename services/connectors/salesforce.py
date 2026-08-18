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
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Protocol, Self
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import (
    ClocksModel,
    ExternalConfirmationBody,
    JsonObject,
    PopulationRecordBody,
)
from services.connectors.base import (
    ActionReference,
    AttributionSurface,
    ConfirmationAccessPath,
    ConfirmationObservation,
    ConnectorCapabilities,
    ConnectorScope,
    EnumerationWindow,
    PopulationObservation,
)

_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_MAX_ASSERTION_LIFETIME = timedelta(minutes=3)
_MAX_AUTH_RESPONSE_BYTES = 1_048_576
_MAX_API_RESPONSE_BYTES = 16 * 1_048_576
_SALESFORCE_ID = re.compile(r"^[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?$")
_API_VERSION = re.compile(r"^v[0-9]+\.[0-9]+$")


class CredentialKeyCustody(StrEnum):
    """Custody of the RSA key used to authenticate to Salesforce."""

    CLIENT_HELD = "client_held"
    HOSTED_KMS = "hosted_kms"


class HostedCredentialCustodyError(ValueError):
    """Hosted key use was attempted without an explicit deployment opt-in."""


class SalesforceAuthError(RuntimeError):
    """Authentication failed without exposing assertions, tokens, or key data."""


class SalesforceApiError(RuntimeError):
    """A Salesforce data API call failed with a stable non-secret code."""

    def __init__(self, message: str, *, status: int | None, error_code: str) -> None:
        super().__init__(message)
        self.status = status
        self.error_code = error_code


class SalesforceQualificationUnavailableError(RuntimeError):
    """C1 use was attempted without a confirmed-clean permission check."""

    def __init__(self, check: SalesforcePermissionCheck) -> None:
        super().__init__(f"Salesforce conditional C1 is unavailable: {check.outcome.value}")
        self.check = check


class AuditFieldPermissionOutcome(StrEnum):
    """Three-state result of the C1 load-bearing permission check."""

    CONFIRMED_CLEAN = "confirmed-clean"
    CONFIRMED_GRANTED = "confirmed-granted"
    CHECK_FAILED = "check-failed"


@dataclass(frozen=True, slots=True)
class UnconfirmedInterval:
    """A closed observation interval whose interior cannot support C1."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        for label, instant in (("start", self.start), ("end", self.end)):
            if instant.tzinfo is None or instant.utcoffset() is None:
                raise ValueError(f"unconfirmed interval {label} must be timezone-aware")
        if self.start >= self.end:
            raise ValueError("unconfirmed interval start must precede end")


@dataclass(frozen=True, slots=True)
class SalesforcePermissionCheck:
    """Permission observation and its conservative coverage consequence.

    A non-clean result after a clean check invalidates the whole interval
    between them. It is intentionally not a prospective-only downgrade.
    """

    outcome: AuditFieldPermissionOutcome
    checked_at: datetime
    last_confirmed_clean_at: datetime | None = None
    failure_code: str | None = None

    def __post_init__(self) -> None:
        if self.checked_at.tzinfo is None or self.checked_at.utcoffset() is None:
            raise ValueError("permission checked_at must be timezone-aware")
        if self.last_confirmed_clean_at is not None:
            if (
                self.last_confirmed_clean_at.tzinfo is None
                or self.last_confirmed_clean_at.utcoffset() is None
            ):
                raise ValueError("last confirmed-clean check must be timezone-aware")
            if self.last_confirmed_clean_at > self.checked_at:
                raise ValueError("last confirmed-clean check cannot follow checked_at")
        if self.outcome is AuditFieldPermissionOutcome.CONFIRMED_CLEAN:
            if self.last_confirmed_clean_at != self.checked_at:
                raise ValueError("a confirmed-clean result becomes the last clean check")
            if self.failure_code is not None:
                raise ValueError("a confirmed-clean result cannot carry a failure code")
        elif self.outcome is AuditFieldPermissionOutcome.CONFIRMED_GRANTED:
            if self.failure_code is not None:
                raise ValueError("a confirmed-granted result cannot carry a failure code")
        elif not self.failure_code:
            raise ValueError("a check-failed result requires a failure code")

    @classmethod
    def confirmed_clean(cls, *, checked_at: datetime) -> Self:
        return cls(
            outcome=AuditFieldPermissionOutcome.CONFIRMED_CLEAN,
            checked_at=checked_at,
            last_confirmed_clean_at=checked_at,
        )

    @classmethod
    def confirmed_granted(
        cls,
        *,
        checked_at: datetime,
        last_confirmed_clean_at: datetime | None = None,
    ) -> Self:
        return cls(
            outcome=AuditFieldPermissionOutcome.CONFIRMED_GRANTED,
            checked_at=checked_at,
            last_confirmed_clean_at=last_confirmed_clean_at,
        )

    @classmethod
    def check_failed(
        cls,
        *,
        checked_at: datetime,
        failure_code: str,
        last_confirmed_clean_at: datetime | None = None,
    ) -> Self:
        return cls(
            outcome=AuditFieldPermissionOutcome.CHECK_FAILED,
            checked_at=checked_at,
            last_confirmed_clean_at=last_confirmed_clean_at,
            failure_code=failure_code,
        )

    @property
    def c1_eligible(self) -> bool:
        return self.outcome is AuditFieldPermissionOutcome.CONFIRMED_CLEAN

    @property
    def maximum_denominator_class(self) -> Literal["C1", "C5"] | None:
        if self.outcome is AuditFieldPermissionOutcome.CONFIRMED_CLEAN:
            return "C1"
        if self.outcome is AuditFieldPermissionOutcome.CONFIRMED_GRANTED:
            return "C5"
        return None

    @property
    def unconfirmed_interval(self) -> UnconfirmedInterval | None:
        if self.c1_eligible or self.last_confirmed_clean_at is None:
            return None
        if self.last_confirmed_clean_at == self.checked_at:
            return None
        return UnconfirmedInterval(self.last_confirmed_clean_at, self.checked_at)

    @property
    def requires_attestation_revisit(self) -> bool:
        return self.unconfirmed_interval is not None


class JwtRs256Signer(Protocol):
    """Opaque RS256 signing capability; raw key bytes never cross this API."""

    @property
    def custody(self) -> CredentialKeyCustody: ...

    @property
    def key_reference(self) -> str: ...

    def sign_rs256(self, message: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True, repr=False)
class FileRs256Signer:
    """Client-provided RSA key file adapter for a hosted connector process.

    The connector never generates or persists this key. The path must resolve
    to a regular file with no group/other permission bits. Key bytes are read
    only inside ``sign_rs256`` and are never exposed as an attribute or repr.
    """

    path: Path

    def __init__(self, path: str | Path) -> None:
        resolved = Path(path).expanduser().resolve(strict=True)
        metadata = resolved.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("RSA private key path must name a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("RSA private key must have no group or other permissions")
        object.__setattr__(self, "path", resolved)

    @property
    def custody(self) -> CredentialKeyCustody:
        return CredentialKeyCustody.CLIENT_HELD

    @property
    def key_reference(self) -> str:
        return str(self.path)

    def sign_rs256(self, message: bytes) -> bytes:
        try:
            key = serialization.load_pem_private_key(
                self.path.read_bytes(), password=None
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("unable to load RSA private key from configured path") from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("configured Salesforce signing key is not RSA")
        if key.key_size < 2048:
            raise ValueError("Salesforce RSA signing key must be at least 2048 bits")
        return key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    def __repr__(self) -> str:
        return f"FileRs256Signer(path={str(self.path)!r})"


@dataclass(frozen=True, slots=True)
class SalesforceJwtBearerConfig:
    """Non-secret External Client App values needed for JWT bearer auth."""

    client_id: str
    subject: str
    audience: str
    assertion_lifetime: timedelta = timedelta(minutes=2)

    @classmethod
    def from_token_endpoint(
        cls,
        *,
        client_id: str,
        subject: str,
        token_endpoint: str,
        assertion_lifetime: timedelta = timedelta(minutes=2),
    ) -> Self:
        suffix = "/services/oauth2/token"
        if not token_endpoint.endswith(suffix):
            raise ValueError(f"token_endpoint must end with {suffix}")
        audience = token_endpoint[: -len(suffix)]
        return cls(
            client_id=client_id,
            subject=subject,
            audience=audience,
            assertion_lifetime=assertion_lifetime,
        )

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


@dataclass(frozen=True, slots=True, repr=False)
class SalesforceAccessToken:
    """Sensitive token exchange result; repr is intentionally disabled."""

    access_token: str
    instance_url: str
    identity_url: str
    token_type: str


@dataclass(frozen=True, slots=True)
class SalesforceIdentity:
    username: str
    user_id: str
    organization_id: str


@dataclass(frozen=True, slots=True)
class SalesforceConnectorConfig:
    """Non-secret, deployment-specific Salesforce connector scope."""

    api_version: str
    integration_user_id: str
    action_family: str = "record.create"
    destination_system: str = "salesforce"
    sobject: str = "Case"
    query_batch_size: int = 2000

    def __post_init__(self) -> None:
        if _API_VERSION.fullmatch(self.api_version) is None:
            raise ValueError("api_version must look like vNN.N")
        if _SALESFORCE_ID.fullmatch(self.integration_user_id) is None:
            raise ValueError("integration_user_id must be a 15- or 18-character Salesforce ID")
        if self.action_family != "record.create":
            raise ValueError("EV-42 is qualified only for record.create")
        if self.destination_system != "salesforce":
            raise ValueError("EV-42 destination_system must be salesforce")
        if self.sobject != "Case":
            raise ValueError("EV-42 is qualified only for the Case object")
        if self.query_batch_size != 2000:
            raise ValueError("EV-42 requires Salesforce query_batch_size 2000")

    @property
    def scope_parameters(self) -> Mapping[str, str]:
        return MappingProxyType(
            {"created_by_id": self.integration_user_id, "sobject": self.sobject}
        )


@dataclass(frozen=True, slots=True)
class SalesforceQueryPage:
    total_size: int
    done: bool
    records: tuple[Mapping[str, object], ...]
    next_records_url: str | None


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


class _RefuseRedirects(HTTPRedirectHandler):
    """Never forward a JWT assertion or bearer token to a redirect target."""

    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def exchange_jwt_bearer(
    request: SalesforceTokenRequest, *, timeout_s: float = 15.0
) -> SalesforceAccessToken:
    """POST one JWT bearer assertion to Salesforce without following redirects."""

    _require_salesforce_https_url(request.url, label="token endpoint")
    encoded_form = urlencode(dict(request.form)).encode("ascii")
    http_request = Request(  # noqa: S310 -- exact HTTPS Salesforce URL validated above
        request.url,
        data=encoded_form,
        headers={**dict(request.headers), "Accept": "application/json"},
        method="POST",
    )
    payload = _open_json(http_request, timeout_s=timeout_s, operation="token exchange")
    access_token = _required_text(payload, "access_token", operation="token exchange")
    instance_url = _required_text(payload, "instance_url", operation="token exchange")
    identity_url = _required_text(payload, "id", operation="token exchange")
    token_type = _required_text(payload, "token_type", operation="token exchange")
    if token_type.lower() != "bearer":
        raise SalesforceAuthError("Salesforce token exchange returned a non-bearer token")
    _require_salesforce_https_url(instance_url, label="instance URL")
    _require_salesforce_https_url(identity_url, label="identity URL")
    return SalesforceAccessToken(
        access_token=access_token,
        instance_url=instance_url.rstrip("/"),
        identity_url=identity_url,
        token_type=token_type,
    )


def confirm_salesforce_identity(
    token: SalesforceAccessToken,
    *,
    expected_username: str,
    timeout_s: float = 15.0,
) -> SalesforceIdentity:
    """Read the OAuth identity resource and bind the token to the expected user."""

    _require_salesforce_https_url(token.identity_url, label="identity URL")
    request = Request(  # noqa: S310 -- exact HTTPS Salesforce URL validated above
        token.identity_url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token.access_token}",
        },
        method="GET",
    )
    payload = _open_json(request, timeout_s=timeout_s, operation="identity check")
    identity = SalesforceIdentity(
        username=_required_text(payload, "username", operation="identity check"),
        user_id=_required_text(payload, "user_id", operation="identity check"),
        organization_id=_required_text(
            payload, "organization_id", operation="identity check"
        ),
    )
    if identity.username != expected_username:
        raise SalesforceAuthError(
            "Salesforce token identity does not match the configured integration user"
        )
    return identity


class SalesforceRestClient:
    """Small authenticated REST client with redirect and host confinement."""

    def __init__(
        self,
        token: SalesforceAccessToken,
        *,
        api_version: str,
        query_batch_size: int = 2000,
    ) -> None:
        if _API_VERSION.fullmatch(api_version) is None:
            raise ValueError("api_version must look like vNN.N")
        if query_batch_size != 2000:
            raise ValueError("EV-42 requires Salesforce query_batch_size 2000")
        _require_salesforce_https_url(token.instance_url, label="instance URL")
        self._token = token
        self.api_version = api_version
        self.query_batch_size = query_batch_size

    def query_page(self, soql: str) -> SalesforceQueryPage:
        if not soql:
            raise ValueError("SOQL query must not be empty")
        return self._query_page(
            f"/services/data/{self.api_version}/query/?{urlencode({'q': soql})}"
        )

    def next_query_page(self, next_records_url: str) -> SalesforceQueryPage:
        if not next_records_url.startswith(
            f"/services/data/{self.api_version}/query/"
        ):
            raise SalesforceApiError(
                "Salesforce returned an invalid nextRecordsUrl",
                status=None,
                error_code="invalid_next_records_url",
            )
        return self._query_page(next_records_url)

    def get_record(self, *, sobject: str, record_id: str) -> Mapping[str, object]:
        if sobject != "Case":
            raise ValueError("EV-42 retrieval is limited to Case")
        if _SALESFORCE_ID.fullmatch(record_id) is None:
            raise ValueError("record_id must be a 15- or 18-character Salesforce ID")
        fields = "Id,CreatedById,CreatedDate,LastModifiedById,OwnerId"
        path = (
            f"/services/data/{self.api_version}/sobjects/{sobject}/{record_id}"
            f"?{urlencode({'fields': fields})}"
        )
        value = self._get_json(path, query_options=False)
        if not isinstance(value, dict):
            raise SalesforceApiError(
                "Salesforce record response was not an object",
                status=None,
                error_code="malformed_record_response",
            )
        return value

    def _query_page(self, path: str) -> SalesforceQueryPage:
        value = self._get_json(path, query_options=True)
        if not isinstance(value, dict):
            raise SalesforceApiError(
                "Salesforce query response was not an object",
                status=None,
                error_code="malformed_query_response",
            )
        total_size = value.get("totalSize")
        done = value.get("done")
        records = value.get("records")
        next_url = value.get("nextRecordsUrl")
        if (
            not isinstance(total_size, int)
            or isinstance(total_size, bool)
            or total_size < 0
            or not isinstance(done, bool)
            or not isinstance(records, list)
            or any(not isinstance(record, dict) for record in records)
            or (next_url is not None and not isinstance(next_url, str))
        ):
            raise SalesforceApiError(
                "Salesforce query response has malformed pagination metadata",
                status=None,
                error_code="malformed_query_response",
            )
        if done and next_url is not None:
            raise SalesforceApiError(
                "Salesforce done response unexpectedly included nextRecordsUrl",
                status=None,
                error_code="contradictory_pagination",
            )
        if not done and not next_url:
            raise SalesforceApiError(
                "Salesforce incomplete response omitted nextRecordsUrl",
                status=None,
                error_code="missing_next_records_url",
            )
        return SalesforceQueryPage(
            total_size=total_size,
            done=done,
            records=tuple(records),
            next_records_url=next_url,
        )

    def _get_json(self, path: str, *, query_options: bool) -> object:
        if not path.startswith("/services/data/"):
            raise SalesforceApiError(
                "Salesforce API path escaped the data API",
                status=None,
                error_code="invalid_api_path",
            )
        url = self._token.instance_url + path
        _require_salesforce_https_url(url, label="data API URL")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token.access_token}",
        }
        if query_options:
            headers["Sforce-Query-Options"] = f"batchSize={self.query_batch_size}"
        request = Request(  # noqa: S310 -- confined Salesforce HTTPS URL above
            url,
            headers=headers,
            method="GET",
        )
        return _open_api_json(request)


class SalesforceConnector:
    """EV-42's conditional-C1 Salesforce Case connector."""

    def __init__(
        self,
        *,
        client: SalesforceRestClient,
        config: SalesforceConnectorConfig,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if client.api_version != config.api_version:
            raise ValueError("REST client and connector API versions must match")
        if client.query_batch_size != config.query_batch_size:
            raise ValueError("REST client and connector query batch sizes must match")
        self._client = client
        self._config = config
        self._now = now or (lambda: datetime.now(UTC))

    def capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            enumeration=True,
            confirmation=True,
            authoritative_time=True,
            settlement_lag=timedelta(0),
            attribution_surface=AttributionSurface.CALLER_SETTABLE_FIELD,
            confirmation_access=ConfirmationAccessPath.SHARED_WITH_ENUMERATION,
        )

    def revalidate_qualification(
        self, *, last_confirmed_clean_at: datetime | None = None
    ) -> SalesforcePermissionCheck:
        checked_at = self._aware_now()
        soql = (  # noqa: S608 -- ID is closed by Salesforce-ID grammar in config
            "SELECT AssigneeId FROM PermissionSetAssignment "  # noqa: S608
            f"WHERE AssigneeId = '{self._config.integration_user_id}' "  # noqa: S608
            "AND PermissionSet.PermissionsCreateAuditFields = true"
        )
        try:
            records, complete, total_size = self._traverse_query(soql)
        except SalesforceApiError as exc:
            return SalesforcePermissionCheck.check_failed(
                checked_at=checked_at,
                last_confirmed_clean_at=last_confirmed_clean_at,
                failure_code=exc.error_code,
            )
        if not complete or total_size != len(records):
            return SalesforcePermissionCheck.check_failed(
                checked_at=checked_at,
                last_confirmed_clean_at=last_confirmed_clean_at,
                failure_code="permission_query_incomplete",
            )
        if records:
            return SalesforcePermissionCheck.confirmed_granted(
                checked_at=checked_at,
                last_confirmed_clean_at=last_confirmed_clean_at,
            )
        return SalesforcePermissionCheck.confirmed_clean(checked_at=checked_at)

    def enumerate(
        self, scope: ConnectorScope, window: EnumerationWindow
    ) -> PopulationObservation:
        self._validate_scope(scope)
        permission = self.revalidate_qualification()
        if not permission.c1_eligible:
            raise SalesforceQualificationUnavailableError(permission)
        soql = _case_enumeration_soql(
            integration_user_id=self._config.integration_user_id,
            window=window,
        )
        retrieved_at = self._aware_now()
        records, pagination_complete, total_size = self._traverse_query(soql)
        identifiers: list[str] = []
        timestamps: list[datetime] = []
        attribution: list[JsonObject] = []
        for record in records:
            record_id = _salesforce_record_text(record, "Id")
            created_by = _salesforce_record_text(record, "CreatedById")
            created_at = _parse_salesforce_timestamp(
                _salesforce_record_text(record, "CreatedDate")
            )
            identifiers.append(record_id)
            timestamps.append(created_at)
            attribution.append(
                {
                    "record_identifier": record_id,
                    "actor_attribute": created_by,
                }
            )
        total_matches = total_size == len(records)
        pagination_complete = pagination_complete and total_matches
        minimum = min(timestamps) if timestamps else None
        maximum = max(timestamps) if timestamps else None
        body = PopulationRecordBody.model_validate(
            {
                "action_family": scope.action_family,
                "destination_system": scope.destination_system,
                "window_start": _timestamp(window.start),
                "window_end": _timestamp(window.end),
                "enumeration_query": {
                    "scope": dict(scope.parameters),
                    "window_start": _timestamp(window.start),
                    "window_end": _timestamp(window.end),
                    "soql": soql,
                },
                "record_identifiers": identifiers,
                "count": len(identifiers),
                "pagination_complete": pagination_complete,
                # Salesforce signalled no result cap. A count disagreement is
                # an incomplete traversal, not evidence that a vendor cap was hit.
                "result_cap_hit": False,
                "retrieved_at": _timestamp(retrieved_at),
                "authoritative_timestamps": {
                    "min": _timestamp(minimum) if minimum is not None else None,
                    "max": _timestamp(maximum) if maximum is not None else None,
                },
                "attribution_observations": attribution,
                "observed_settlement_lag_ms": 0,
                "qualification_condition": permission.outcome.value,
                "total_size_matches": total_matches,
            }
        )
        clocks_data: dict[str, str] = {"source_time": _timestamp(retrieved_at)}
        if maximum is not None:
            clocks_data["authoritative_time"] = _timestamp(maximum)
        return PopulationObservation(
            body=body,
            clocks=ClocksModel.model_validate(clocks_data),
            source=self._source(),
        )

    def confirm(self, action_ref: ActionReference) -> ConfirmationObservation:
        retrieved_at = self._aware_now()
        record = self._client.get_record(
            sobject=self._config.sobject,
            record_id=action_ref.destination_record_id,
        )
        authoritative = _parse_salesforce_timestamp(
            _salesforce_record_text(record, "CreatedDate")
        )
        digest = "sha256:" + sha256(canonicalize(record)).hexdigest()
        return ConfirmationObservation(
            body=ExternalConfirmationBody(
                action_id=action_ref.action_id,
                destination_system=self._config.destination_system,
                destination_record_id=action_ref.destination_record_id,
                destination_record_digest=digest,
                authoritative_timestamp=_timestamp(authoritative),
                reconciliation_status="matched",
                retrieved_at=_timestamp(retrieved_at),
            ),
            clocks=ClocksModel(
                source_time=_timestamp(retrieved_at),
                authoritative_time=_timestamp(authoritative),
            ),
            source=self._source(),
        )

    def _traverse_query(
        self, soql: str
    ) -> tuple[list[Mapping[str, object]], bool, int]:
        page = self._client.query_page(soql)
        expected_total = page.total_size
        records = list(page.records)
        seen_urls: set[str] = set()
        while not page.done:
            next_url = page.next_records_url
            if next_url is None or next_url in seen_urls:
                return records, False, expected_total
            seen_urls.add(next_url)
            try:
                page = self._client.next_query_page(next_url)
            except SalesforceApiError:
                return records, False, expected_total
            if page.total_size != expected_total:
                return records, False, expected_total
            records.extend(page.records)
        return records, True, expected_total

    def _validate_scope(self, scope: ConnectorScope) -> None:
        if (
            scope.action_family != self._config.action_family
            or scope.destination_system != self._config.destination_system
            or dict(scope.parameters) != dict(self._config.scope_parameters)
        ):
            raise ValueError("scope does not match the qualified Salesforce deployment")

    def _aware_now(self) -> datetime:
        value = self._now()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("connector clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _source(self) -> JsonObject:
        return {
            "connector": "salesforce",
            "destination_system": self._config.destination_system,
            "api_version": self._config.api_version,
            "sobject": self._config.sobject,
        }


def _case_enumeration_soql(
    *, integration_user_id: str, window: EnumerationWindow
) -> str:
    if _SALESFORCE_ID.fullmatch(integration_user_id) is None:
        raise ValueError("integration_user_id must be a Salesforce ID")
    return (  # noqa: S608 -- ID grammar and typed timestamps close interpolation
        "SELECT Id, CreatedById, CreatedDate, LastModifiedById, OwnerId FROM Case "  # noqa: S608
        f"WHERE CreatedById = '{integration_user_id}' "  # noqa: S608
        f"AND CreatedDate >= {_soql_timestamp(window.start)} "
        f"AND CreatedDate < {_soql_timestamp(window.end)} "
        "ORDER BY CreatedDate ASC, Id ASC"
    )


def _salesforce_record_text(record: Mapping[str, object], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise SalesforceApiError(
            f"Salesforce record omitted {field}",
            status=None,
            error_code="malformed_record_response",
        )
    return value


def _parse_salesforce_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SalesforceApiError(
            "Salesforce returned an invalid timestamp",
            status=None,
            error_code="malformed_record_response",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SalesforceApiError(
            "Salesforce returned a timestamp without an offset",
            status=None,
            error_code="malformed_record_response",
        )
    return parsed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _soql_timestamp(value: datetime) -> str:
    return _timestamp(value)


def _open_api_json(request: Request, *, timeout_s: float = 30.0) -> object:
    opener = build_opener(_RefuseRedirects())
    try:
        with opener.open(request, timeout=timeout_s) as response:
            raw = response.read(_MAX_API_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        error_code = _salesforce_data_error_code(exc)
        raise SalesforceApiError(
            f"Salesforce data API failed with HTTP {exc.code} ({error_code})",
            status=exc.code,
            error_code=error_code,
        ) from None
    except (TimeoutError, URLError, OSError):
        raise SalesforceApiError(
            "Salesforce data API could not be completed",
            status=None,
            error_code="transport_failure",
        ) from None
    if len(raw) > _MAX_API_RESPONSE_BYTES:
        raise SalesforceApiError(
            "Salesforce data API response exceeded size limit",
            status=None,
            error_code="response_too_large",
        )
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SalesforceApiError(
            "Salesforce data API returned malformed JSON",
            status=None,
            error_code="malformed_json",
        ) from None


def _salesforce_data_error_code(error: HTTPError) -> str:
    try:
        value: object = json.loads(error.read(_MAX_API_RESPONSE_BYTES))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "unparseable_error"
    if isinstance(value, list) and value and isinstance(value[0], dict):
        code = value[0].get("errorCode")
        if isinstance(code, str):
            return code
    if isinstance(value, dict):
        code = value.get("errorCode") or value.get("error")
        if isinstance(code, str):
            return code
    return "unspecified_error"


def _open_json(request: Request, *, timeout_s: float, operation: str) -> Mapping[str, object]:
    if timeout_s <= 0:
        raise ValueError("timeout_s must be positive")
    opener = build_opener(_RefuseRedirects())
    try:
        with opener.open(request, timeout=timeout_s) as response:
            raw = response.read(_MAX_AUTH_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        code = _salesforce_error_code(exc)
        raise SalesforceAuthError(
            f"Salesforce {operation} failed with HTTP {exc.code} ({code})"
        ) from None
    except (TimeoutError, URLError, OSError):
        raise SalesforceAuthError(f"Salesforce {operation} could not be completed") from None
    if len(raw) > _MAX_AUTH_RESPONSE_BYTES:
        raise SalesforceAuthError(f"Salesforce {operation} response exceeded size limit")
    try:
        value: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SalesforceAuthError(
            f"Salesforce {operation} returned malformed JSON"
        ) from None
    if not isinstance(value, dict):
        raise SalesforceAuthError(f"Salesforce {operation} returned a non-object response")
    return value


def _salesforce_error_code(error: HTTPError) -> str:
    try:
        raw = error.read(_MAX_AUTH_RESPONSE_BYTES)
        value: object = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "unparseable_error"
    if isinstance(value, dict) and isinstance(value.get("error"), str):
        return str(value["error"])
    return "unspecified_error"


def _required_text(
    payload: Mapping[str, object], name: str, *, operation: str
) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise SalesforceAuthError(
            f"Salesforce {operation} omitted required field {name}"
        )
    return value


def _require_salesforce_https_url(value: str, *, label: str) -> None:
    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or not _is_salesforce_hostname(hostname)
    ):
        raise SalesforceAuthError(f"Salesforce {label} is not an allowed HTTPS URL")


def _is_salesforce_hostname(hostname: str) -> bool:
    return hostname == "salesforce.com" or hostname.endswith(
        (".salesforce.com", ".force.com")
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
