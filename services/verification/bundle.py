"""Cold-built Python verification of signed attestation bundles (EV-41)."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from sdk_python.evidence.bundle import (
    Bundle as AttestationBundle,
)
from sdk_python.evidence.bundle import (
    BundleError,
    BundleOrderError,
    BundleShapeError,
    NonCanonicalBundleError,
    parse_bundle,
)
from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.chain import (
    RegisteredPublicKey as SDKRegisteredPublicKey,
)
from sdk_python.evidence.chain import (
    verify_key_continuity,
)
from sdk_python.evidence.schema import (
    AttestationWindowRecord,
    CoverageGapRecord,
    PopulationRecord,
    QualificationRecord,
    RevocationRecord,
)
from sdk_python.evidence.signing import SignatureError
from sdk_python.evidence.versions import (
    METHODOLOGY_VERSION_REGISTRY,
    UnpublishedVersionError,
    published_versions,
    require_published_methodology_version,
    require_published_schema_version,
)
from services.ingestion.receipts import (
    KeyNamespaceError,
    RegisteredPublicKey,
    parse_canonical_record_wire,
    parse_timestamp,
    verify_record_origin_signature,
)

PUBLISHED_METHODOLOGY_VERSIONS = published_versions(METHODOLOGY_VERSION_REGISTRY)
ASSERTION_CATALOGUE = frozenset(f"A-{index:02d}" for index in range(1, 11))
COUNT_FIELDS = (
    "matched",
    "unmatched_with_evidence",
    "unmatched_without_evidence",
    "duplicate",
    "ambiguous",
    "out_of_scope",
)
LEVEL_ORDER = ("observed", "intercepted", "enforced", "reconciled")
CLASS_CEILING = {
    "C1": "reconciled",
    "C2": "reconciled",
    "C3": "enforced",
    "C4": "observed",
    "C5": "observed",
}
CLASS_RANK = {"C1": 0, "C2": 1, "C3": 2, "C4": 3, "C5": 4}


class BundleVerificationError(ValueError):
    """A signed bundle makes a claim its carried evidence does not support."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RevocationResponse:
    status_code: int
    body: bytes | None = None


@dataclass(frozen=True, slots=True)
class RevocationResult:
    status: str
    checked: bool
    effective_at: str | None = None
    superseding_ref: str | None = None
    pending: bool = False


@dataclass(frozen=True, slots=True)
class BundleVerificationResult:
    accepted: bool
    verdict: str
    evaluated_at: str
    attestation_id: str | None
    revocation_status: str
    coverage_ratio: str | None
    error_codes: tuple[str, ...] = ()
    unchecked: tuple[str, ...] = ()
    pending_revocation_effective_at: str | None = None
    superseding_ref: str | None = None

    def to_vector_result(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "accepted": self.accepted,
            "verdict": self.verdict,
            "evaluated_at": self.evaluated_at,
            "revocation_status": self.revocation_status,
            "coverage_ratio": self.coverage_ratio,
            "unchecked": list(self.unchecked),
        }
        if self.attestation_id is not None:
            result["attestation_id"] = self.attestation_id
        if self.error_codes:
            result["error_codes"] = list(self.error_codes)
        if self.pending_revocation_effective_at is not None:
            result["pending_revocation_effective_at"] = self.pending_revocation_effective_at
        if self.superseding_ref is not None:
            result["superseding_ref"] = self.superseding_ref
        return result


def _instant(value: datetime | str) -> datetime:
    parsed = parse_timestamp(value) if isinstance(value, str) else value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BundleVerificationError(
            "evaluation.instant_invalid", "evaluation instant must have an explicit offset"
        )
    return parsed


def _evaluated_at(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _attestation_id_after_verified_parse(wire: bytes) -> str | None:
    """Recover the already-verified attestation ID after a methodology refusal.

    ``parse_bundle`` checks every schema and signature before it checks the
    attestation methodology. Re-reading only the ID here preserves that useful
    diagnostic without treating a failed schema parse as an authenticated
    identity.
    """

    decoded = json.loads(wire)
    if not isinstance(decoded, list):
        return None
    for value in decoded:
        if isinstance(value, dict) and value.get("record_type") == "AttestationWindow":
            record_id = value.get("record_id")
            return record_id if isinstance(record_id, str) else None
    return None


def _stream_checks(
    bundle: AttestationBundle, verification_keys: Mapping[str, RegisteredPublicKey]
) -> tuple[str, ...]:
    grouped: dict[str, list[Any]] = {}
    for record in bundle.records:
        grouped.setdefault(record.stream_id, []).append(record)
    unchecked: list[str] = []
    for stream_id, records in sorted(grouped.items()):
        ordered = sorted(records, key=lambda record: record.sequence)
        positions: dict[int, Any] = {}
        for record in ordered:
            previous_at_position = positions.get(record.sequence)
            if previous_at_position is not None and canonical_digest(
                previous_at_position
            ) != canonical_digest(record):
                raise BundleVerificationError(
                    "chain.fork",
                    f"stream {stream_id!r} has two records at sequence {record.sequence}",
                )
            positions[record.sequence] = record
        unique = [positions[position] for position in sorted(positions)]
        first = unique[0]
        if first.sequence == 1 and first.prev_digest is not None:
            raise BundleVerificationError(
                "chain.prev_digest_mismatch", "sequence 1 must carry null prev_digest"
            )
        if first.sequence > 1:
            unchecked.append(f"chain:{stream_id}:before:{first.sequence}")
        previous = first
        previous_key = verify_record_origin_signature(previous, verification_keys=verification_keys)
        previous_namespace = verification_keys[previous_key].namespace
        for current in unique[1:]:
            if current.sequence != previous.sequence + 1:
                unchecked.append(f"chain:{stream_id}:{previous.sequence}:{current.sequence}")
                previous = current
                previous_key = verify_record_origin_signature(
                    previous, verification_keys=verification_keys
                )
                previous_namespace = verification_keys[previous_key].namespace
                continue
            if current.prev_digest != canonical_digest(previous):
                raise BundleVerificationError(
                    "chain.prev_digest_mismatch",
                    f"stream {stream_id!r} has a broken link at sequence {current.sequence}",
                )
            current_key = verify_record_origin_signature(
                current, verification_keys=verification_keys
            )
            current_namespace = verification_keys[current_key].namespace
            if current_namespace != previous_namespace:
                raise BundleVerificationError(
                    "key.namespace_mismatch",
                    f"stream {stream_id!r} changes primary-signer namespace",
                )
            continuity = current.signature.get("key_continuity")
            if current_key != previous_key:
                if not isinstance(continuity, dict):
                    raise BundleVerificationError(
                        "continuity.missing",
                        f"stream {stream_id!r} changes key without continuity",
                    )
                verify_key_continuity(
                    continuity,
                    expected_predecessor_key_id=previous_key,
                    predecessor_public_key=verification_keys[previous_key].public_key,
                    expected_new_key_id=current_key,
                    new_public_key=verification_keys[current_key].public_key,
                    expected_tenant_id=current.tenant_id,
                    expected_stream_id=current.stream_id,
                )
            elif continuity is not None:
                raise BundleVerificationError(
                    "continuity.no_key_change", "key continuity is present without a key change"
                )
            previous = current
            previous_key = current_key
            previous_namespace = current_namespace
    return tuple(unchecked)


def _counts(attestation: AttestationWindowRecord) -> dict[str, int]:
    raw = attestation.body.counts
    if set(raw) != set(COUNT_FIELDS):
        raise BundleVerificationError(
            "coverage.counts_invalid", "counts must contain exactly the six CM-012 classes"
        )
    result: dict[str, int] = {}
    for name in COUNT_FIELDS:
        value = raw[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise BundleVerificationError(
                "coverage.counts_invalid", f"counts.{name} must be a non-negative integer"
            )
        result[name] = value
    return result


def _ratio_checks(bundle: AttestationBundle) -> tuple[str | None, tuple[str, ...]]:
    attestation = bundle.attestation
    try:
        require_published_methodology_version(attestation.body.methodology_version)
    except UnpublishedVersionError as exc:
        raise BundleVerificationError(
            "methodology.version_unsupported", str(exc)
        ) from exc
    refs = attestation.body.population_record_refs
    if len(refs) != len(set(refs)):
        raise BundleVerificationError(
            "coverage.population_ref_duplicate", "population_record_refs must not repeat"
        )
    by_id = {record.record_id: record for record in bundle.records}
    population: list[PopulationRecord] = []
    for ref in refs:
        record = by_id.get(ref)
        if not isinstance(record, PopulationRecord):
            raise BundleVerificationError(
                "coverage.population_missing", f"population reference {ref!r} is not carried"
            )
        if (
            record.tenant_id != attestation.tenant_id
            or record.boundary_ref != attestation.boundary_ref
        ):
            raise BundleVerificationError(
                "coverage.scope_mismatch",
                f"population reference {ref!r} is outside attestation scope",
            )
        population.append(record)

    counts = _counts(attestation)
    total = sum(record.body.count for record in population)
    independently_enumerable = attestation.body.denominator_class in {"C1", "C2", "C3"}
    if independently_enumerable and sum(counts.values()) != total:
        raise BundleVerificationError(
            "coverage.count_conservation",
            f"six reconciliation counts total {sum(counts.values())}, population is {total}",
        )
    denominator = total - counts["out_of_scope"]
    ratio: str | None
    unavailable = (
        attestation.body.denominator_class in {"C4", "C5"}
        or denominator == 0
        or any(
            record.body.result_cap_hit or not record.body.pagination_complete
            for record in population
        )
    )
    if unavailable:
        ratio = None
    else:
        scaled = counts["matched"] * 10_000 // denominator
        ratio = f"{scaled // 10_000}.{scaled % 10_000:04d}"
    if attestation.body.coverage_ratio != ratio:
        raise BundleVerificationError(
            "coverage.ratio_mismatch",
            f"coverage_ratio is {attestation.body.coverage_ratio!r}; recomputed value is {ratio!r}",
        )
    unchecked = () if independently_enumerable else ("coverage.count_conservation",)
    return ratio, unchecked


def _assertion_checks(attestation: AttestationWindowRecord) -> tuple[str, ...]:
    unchecked: list[str] = []
    for index, assertion in enumerate(attestation.body.assertions):
        if not isinstance(assertion, dict):
            raise BundleVerificationError(
                "assertion.invalid", f"assertion {index} is not an object"
            )
        assertion_id = assertion.get("assertion_id")
        if assertion_id not in ASSERTION_CATALOGUE:
            raise BundleVerificationError(
                "assertion.outside_catalogue",
                f"assertion {index} names non-catalogue ID {assertion_id!r}",
            )
        # AR-003 closes the IDs, but no normative wire schema defines the
        # remaining members of a catalogue assertion. Claiming those
        # caller-authored members were verified would invent that missing rule.
        unchecked.append(f"assertion.payload:{assertion_id}")
    return tuple(unchecked)


def _lattice_checks(attestation: AttestationWindowRecord) -> tuple[str, ...]:
    claimed = attestation.body.coverage_level
    ceiling = CLASS_CEILING[attestation.body.denominator_class]
    if claimed not in LEVEL_ORDER:
        raise BundleVerificationError(
            "coverage.level_invalid", f"unknown coverage level {claimed!r}"
        )
    if LEVEL_ORDER.index(claimed) > LEVEL_ORDER.index(ceiling):
        raise BundleVerificationError(
            "coverage.level_exceeds_class",
            f"{claimed} exceeds {attestation.body.denominator_class}'s {ceiling} ceiling",
        )
    raw_body = attestation.body.model_dump(mode="json", exclude_unset=True)
    capped = raw_body.get("capped_by_class")
    if capped is not None and not isinstance(capped, bool):
        raise BundleVerificationError(
            "coverage.capped_by_class_invalid", "capped_by_class must be a boolean"
        )
    if LEVEL_ORDER.index(claimed) < LEVEL_ORDER.index(ceiling) and capped is True:
        raise BundleVerificationError(
            "coverage.capped_by_class_invalid",
            "a claim below the class ceiling is determinately not capped by class",
        )
    if claimed == ceiling:
        return ("coverage.capped_by_class",)
    return ()


def _gap_key(value: Mapping[str, Any]) -> tuple[object, object, object, bytes]:
    return (
        value.get("gap_start", value.get("start")),
        value.get("gap_end", value.get("end")),
        value.get("cause"),
        canonicalize(value.get("affected_scope")),
    )


def _gap_checks(bundle: AttestationBundle) -> None:
    announced: set[tuple[object, object, object, bytes]] = set()
    for index, value in enumerate(bundle.attestation.body.gaps):
        if not isinstance(value, dict):
            raise BundleVerificationError(
                "coverage.gap_invalid", f"attestation gap {index} is not an object"
            )
        start = value.get("gap_start", value.get("start"))
        end = value.get("gap_end", value.get("end"))
        if (
            not isinstance(start, str)
            or not isinstance(end, str)
            or value.get("cause") is None
            or value.get("affected_scope") is None
        ):
            raise BundleVerificationError(
                "coverage.gap_invalid",
                f"attestation gap {index} must state interval, scope, and cause",
            )
        if parse_timestamp(end) <= parse_timestamp(start):
            raise BundleVerificationError(
                "coverage.gap_invalid", f"attestation gap {index} has an empty interval"
            )
        announced.add(_gap_key(value))
    for record in bundle.of_type("CoverageGap"):
        if not isinstance(record, CoverageGapRecord):  # pragma: no cover - dispatch contract
            continue
        body = record.body.model_dump(mode="json", exclude_unset=True)
        if _gap_key(body) not in announced:
            raise BundleVerificationError(
                "coverage.gap_unreported",
                f"signed CoverageGap {record.record_id} is omitted from attestation gaps",
            )


def _qualification_checks(bundle: AttestationBundle) -> tuple[str, ...]:
    attestation = bundle.attestation
    boundary = bundle.boundary
    if boundary is None:
        return ("qualification.class_in_force",)
    if (
        boundary.record_id != attestation.body.boundary_ref
        and boundary.boundary_ref != attestation.body.boundary_ref
    ):
        raise BundleVerificationError(
            "qualification.boundary_mismatch", "AssuranceBoundary does not match attestation"
        )
    by_id = {record.record_id: record for record in bundle.records}
    referenced: list[QualificationRecord] = []
    undisclosed = False
    for ref in boundary.body.qualification_refs:
        record = by_id.get(ref)
        if record is None:
            undisclosed = True
            continue
        if not isinstance(record, QualificationRecord):
            raise BundleVerificationError(
                "qualification.reference_invalid", f"qualification reference {ref!r} has wrong type"
            )
        referenced.append(record)
    if not referenced or undisclosed:
        return ("qualification.class_in_force",)

    claimed = attestation.body.denominator_class
    window_start = parse_timestamp(attestation.body.window_start)
    window_end = parse_timestamp(attestation.body.window_end)
    histories: dict[tuple[str, str], list[QualificationRecord]] = {}
    for record in referenced:
        histories.setdefault(
            (record.body.action_family, record.body.destination_system), []
        ).append(record)
    for scope, history in sorted(histories.items()):
        before = [
            record
            for record in history
            if parse_timestamp(record.body.qualified_at) < window_start
        ]
        if not before:
            raise BundleVerificationError(
                "qualification.postdates_window", "qualification postdates window"
            )
        governing = max(before, key=lambda record: parse_timestamp(record.body.qualified_at))
        in_window = [
            record
            for record in history
            if window_start <= parse_timestamp(record.body.qualified_at) < window_end
        ]
        in_force_rank = max(
            CLASS_RANK[record.body.assigned_class] for record in (governing, *in_window)
        )
        if CLASS_RANK[claimed] < in_force_rank:
            later_support = [
                record
                for record in history
                if CLASS_RANK[record.body.assigned_class] <= CLASS_RANK[claimed]
                and parse_timestamp(record.body.qualified_at) >= window_start
            ]
            if later_support:
                raise BundleVerificationError(
                    "qualification.postdates_window", "qualification postdates window"
                )
            raise BundleVerificationError(
                "qualification.class_unsupported",
                f"claimed class {claimed} exceeds class in force for {scope!r}",
            )
    return ()


def _validity_status(attestation: AttestationWindowRecord, evaluated_at: datetime) -> str:
    valid_from = parse_timestamp(attestation.body.validity_from)
    valid_until = parse_timestamp(attestation.body.validity_until)
    if valid_until <= valid_from:
        raise BundleVerificationError(
            "validity.interval_invalid", "validity_until must follow validity_from"
        )
    if evaluated_at < valid_from:
        return "not_yet_valid"
    if evaluated_at >= valid_until:
        return "expired"
    return "current"


def check_revocation(
    attestation: AttestationWindowRecord,
    *,
    response: RevocationResponse | None,
    verification_keys: Mapping[str, RegisteredPublicKey],
    evaluated_at: datetime,
) -> RevocationResult:
    """Classify one AR-029 endpoint response; unauthenticated data establishes nothing."""

    if response is None:
        return RevocationResult(status="unchecked", checked=False)
    if response.status_code == 404:
        return RevocationResult(status="valid", checked=True)
    if response.status_code != 200 or response.body is None:
        return RevocationResult(status="unchecked", checked=False)
    try:
        record, _ = parse_canonical_record_wire(response.body)
        if not isinstance(record, RevocationRecord):
            return RevocationResult(status="unchecked", checked=False)
        require_published_schema_version(record.schema_version)
        verify_record_origin_signature(record, verification_keys=verification_keys)
        if record.body.attestation_ref != attestation.record_id:
            return RevocationResult(status="unchecked", checked=False)
        effective = parse_timestamp(record.body.effective_at)
    except (ValueError, SignatureError, KeyNamespaceError):
        return RevocationResult(status="unchecked", checked=False)
    if effective > evaluated_at:
        return RevocationResult(
            status="valid",
            checked=True,
            effective_at=record.body.effective_at,
            superseding_ref=record.body.superseding_ref,
            pending=True,
        )
    if record.body.superseding_ref is None:
        return RevocationResult(
            status="revoked", checked=True, effective_at=record.body.effective_at
        )
    return RevocationResult(
        status="superseded",
        checked=True,
        effective_at=record.body.effective_at,
        superseding_ref=record.body.superseding_ref,
    )


def fetch_revocation(
    endpoint: str,
    attestation_id: str,
    *,
    opener: Callable[[str], RevocationResponse] | None = None,
) -> RevocationResponse | None:
    """Perform AR-029's exact GET path, returning ``None`` when nothing is established."""

    url = f"{endpoint.rstrip('/')}/revocations/{attestation_id}"
    if opener is not None:
        try:
            return opener(url)
        except OSError:
            return None
    try:
        with urlopen(url, timeout=5) as response:  # noqa: S310 - caller chooses issuer endpoint
            return RevocationResponse(status_code=response.status, body=response.read())
    except HTTPError as exc:
        if exc.code == 404:
            return RevocationResponse(status_code=404)
        return RevocationResponse(status_code=exc.code)
    except (URLError, OSError):
        return None


def verify_attestation_bundle(
    raw_bundle: bytes | str,
    *,
    verification_keys: Mapping[str, RegisteredPublicKey],
    evaluated_at: datetime | str,
    revocation_response: RevocationResponse | None = None,
) -> BundleVerificationResult:
    """Verify a bundle from its canonical wire bytes and return a closed verdict."""

    instant = _instant(evaluated_at)
    rendered_instant = _evaluated_at(instant)
    attestation: AttestationWindowRecord | None = None
    try:
        wire = raw_bundle.encode("utf-8") if isinstance(raw_bundle, str) else raw_bundle
        bundle = parse_bundle(
            wire,
            verification_keys=cast(
                Mapping[str, SDKRegisteredPublicKey], verification_keys
            ),
        )
        attestation = bundle.attestation
        unchecked = list(_stream_checks(bundle, verification_keys))
        ratio, ratio_unchecked = _ratio_checks(bundle)
        unchecked.extend(ratio_unchecked)
        unchecked.extend(_assertion_checks(attestation))
        unchecked.extend(_lattice_checks(attestation))
        _gap_checks(bundle)
        unchecked.extend(_qualification_checks(bundle))
        validity = _validity_status(attestation, instant)
        revocation = check_revocation(
            attestation,
            response=revocation_response,
            verification_keys=verification_keys,
            evaluated_at=instant,
        )
    except BundleVerificationError as exc:
        return BundleVerificationResult(
            accepted=False,
            verdict="invalid",
            evaluated_at=rendered_instant,
            attestation_id=attestation.record_id if attestation is not None else None,
            revocation_status="unchecked",
            coverage_ratio=None,
            error_codes=(exc.code,),
        )
    except BundleError as exc:
        if isinstance(exc, NonCanonicalBundleError):
            code = "bundle.non_canonical"
        elif isinstance(exc, BundleOrderError):
            code = "bundle.element_order"
        elif isinstance(exc, BundleShapeError):
            code = "bundle.container_invalid"
        else:
            code = "bundle.invalid"
        return BundleVerificationResult(
            accepted=False,
            verdict="invalid",
            evaluated_at=rendered_instant,
            attestation_id=attestation.record_id if attestation is not None else None,
            revocation_status="unchecked",
            coverage_ratio=None,
            error_codes=(code,),
        )
    except UnpublishedVersionError as exc:
        methodology_error = "methodology_version" in str(exc)
        code = (
            "methodology.version_unsupported"
            if methodology_error
            else "schema.version_unsupported"
        )
        return BundleVerificationResult(
            accepted=False,
            verdict="invalid",
            evaluated_at=rendered_instant,
            attestation_id=(
                _attestation_id_after_verified_parse(wire)
                if methodology_error
                else None
            ),
            revocation_status="unchecked",
            coverage_ratio=None,
            error_codes=(code,),
        )
    except (ValueError, SignatureError, KeyNamespaceError):
        return BundleVerificationResult(
            accepted=False,
            verdict="invalid",
            evaluated_at=rendered_instant,
            attestation_id=attestation.record_id if attestation is not None else None,
            revocation_status="unchecked",
            coverage_ratio=None,
            error_codes=("signature.invalid",),
        )

    if validity != "current":
        verdict = validity
    elif revocation.status in {"revoked", "superseded"}:
        verdict = revocation.status
    elif not revocation.checked:
        verdict = "unchecked_revocation"
    elif unchecked:
        verdict = "unchecked"
    else:
        verdict = "valid"
    return BundleVerificationResult(
        accepted=True,
        verdict=verdict,
        evaluated_at=rendered_instant,
        attestation_id=attestation.record_id,
        revocation_status=revocation.status,
        coverage_ratio=ratio,
        unchecked=tuple(sorted(set(unchecked))),
        pending_revocation_effective_at=(revocation.effective_at if revocation.pending else None),
        superseding_ref=revocation.superseding_ref,
    )


__all__ = [
    "ASSERTION_CATALOGUE",
    "BundleVerificationError",
    "BundleVerificationResult",
    "PUBLISHED_METHODOLOGY_VERSIONS",
    "RevocationResponse",
    "RevocationResult",
    "check_revocation",
    "fetch_revocation",
    "verify_attestation_bundle",
]
