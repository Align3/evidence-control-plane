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
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Protocol, Self
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_MAX_ASSERTION_LIFETIME = timedelta(minutes=3)
_MAX_AUTH_RESPONSE_BYTES = 1_048_576


class CredentialKeyCustody(StrEnum):
    """Custody of the RSA key used to authenticate to Salesforce."""

    CLIENT_HELD = "client_held"
    HOSTED_KMS = "hosted_kms"


class HostedCredentialCustodyError(ValueError):
    """Hosted key use was attempted without an explicit deployment opt-in."""


class SalesforceAuthError(RuntimeError):
    """Authentication failed without exposing assertions, tokens, or key data."""


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
