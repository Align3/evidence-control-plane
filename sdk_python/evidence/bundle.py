"""The attestation bundle container (ES-034).

A bundle is a JSON *array* of complete signed records, and every routing
decision in this module is taken from the record's own ``record_type`` under the
closed ES-033 dispatch.  Nothing here reads a record's role from where it sits.

That is worth stating as a property rather than as a coding style, because the
container shape decides whether it can be violated at all.  A mapping from a
role name to a record — ``{"attestation": ..., "gaps": [...]}`` — makes the
role a *second*, independent statement about each record, supplied by whoever
assembled the container and not covered by the record's own signature.  Two
statements that can disagree eventually do: a ``PopulationRecord`` filed under
``gaps`` is either counted as a gap, or triggers a mismatch check that the
array form never needs.  An array has no such second statement to disagree
with, so the parser cannot be handed the wrong answer.  ``parse_bundle``
therefore refuses any container that is not an array, including one whose keys
would have been consistent with its contents.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, cast

from sdk_python.evidence.canonical import canonical_digest, canonicalize
from sdk_python.evidence.chain import RegisteredPublicKey
from sdk_python.evidence.schema import (
    AssuranceBoundaryRecord,
    AttestationWindowRecord,
    EvidenceRecord,
    RecordEnvelope,
    _constant_is_forbidden,
    _duplicate_safe_object,
    _float_token_is_forbidden,
    validate_record,
)
from sdk_python.evidence.versions import (
    require_published_methodology_version,
    require_published_schema_version,
)

#: ES-034 cardinality. Every other §5 type may appear any number of times.
REQUIRED_SINGLETON: Final = "AttestationWindow"
OPTIONAL_SINGLETON: Final = "AssuranceBoundary"


class BundleError(ValueError):
    """Base class for a bundle this verifier refuses to read."""


class BundleShapeError(BundleError):
    """The container is not the ES-034 array of complete signed records."""


class NonCanonicalBundleError(BundleError):
    """The bundle's bytes are not the RFC 8785 canonical form of its content.

    Separate from every signature error on purpose: ES-S-023 requires the
    failure to name the canonical form rather than a signature, so that a
    producer emitting valid records through a sloppy serializer is told what is
    actually wrong instead of hunting a key mismatch that does not exist.
    """


class BundleOrderError(BundleError):
    """Elements are not in ascending canonical-byte order."""


class BundleCardinalityError(BundleError):
    """The bundle does not carry the ES-034 required or permitted record counts."""


@dataclass(frozen=True, slots=True)
class StreamLink:
    """One ES-006a link position within a bundle's slice of a stream.

    ES-034 preserves ES-026 selective disclosure, so a bundle is expected to
    carry slices.  A link is ``checked`` only where two records sit at
    consecutive sequences; across an omission it is ``unchecked``, which is
    neither verified nor broken and MUST NOT be reported as either.
    """

    stream_id: str
    from_sequence: int
    to_sequence: int
    checked: bool


class BrokenStreamLinkError(BundleError):
    """Two consecutive records in a bundle do not link under ES-006a."""


@dataclass(frozen=True, slots=True)
class Bundle:
    """A parsed, verified ES-034 bundle.

    ``records`` preserves the array exactly as received.  ``by_type`` is a
    derived index and every entry in it was placed there by reading the
    record's own ``record_type``.
    """

    records: tuple[EvidenceRecord, ...]
    by_type: Mapping[str, tuple[EvidenceRecord, ...]]
    canonical_bytes: bytes
    stream_links: tuple[StreamLink, ...]

    @property
    def attestation(self) -> AttestationWindowRecord:
        """The single ES-034 ``AttestationWindow``."""

        attestation = self.by_type[REQUIRED_SINGLETON][0]
        assert isinstance(attestation, AttestationWindowRecord)
        return attestation

    @property
    def boundary(self) -> AssuranceBoundaryRecord | None:
        """The at-most-one ``AssuranceBoundary``, if the bundle discloses it."""

        boundaries = self.by_type.get(OPTIONAL_SINGLETON, ())
        if not boundaries:
            return None
        boundary = boundaries[0]
        assert isinstance(boundary, AssuranceBoundaryRecord)
        return boundary

    def of_type(self, record_type: str) -> tuple[EvidenceRecord, ...]:
        """Records whose own ``record_type`` is ``record_type``."""

        return self.by_type.get(record_type, ())

    @property
    def unchecked_links(self) -> tuple[StreamLink, ...]:
        return tuple(link for link in self.stream_links if not link.checked)


def _decode_array(raw: bytes | str) -> list[Any]:
    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=_duplicate_safe_object,
            parse_float=_float_token_is_forbidden,
            parse_constant=_constant_is_forbidden,
        )
    except json.JSONDecodeError as exc:
        raise BundleShapeError(f"bundle is not well-formed JSON: {exc}") from exc
    except ValueError as exc:
        # A duplicate member, a float, or NaN, refused during decoding rather
        # than normalized into something with a second canonical form.
        raise BundleShapeError(f"bundle carries a non-conformant JSON value: {exc}") from exc
    if isinstance(decoded, dict):
        raise BundleShapeError(
            "bundle is a JSON object; ES-034 defines the container as an array of "
            "complete signed records, and a keyed container would state each "
            "record's role a second time outside the signature that covers it"
        )
    if not isinstance(decoded, list):
        raise BundleShapeError("bundle must be a JSON array of complete signed records")
    return decoded


def _require_canonical(raw: bytes, decoded: Sequence[Any]) -> bytes:
    canonical = canonicalize(list(decoded))
    if canonical != raw:
        raise NonCanonicalBundleError(
            "bundle is not RFC 8785 canonical: the received bytes differ from the "
            "canonical form of the same content"
        )
    return canonical


def _require_ascending(elements: Sequence[bytes]) -> None:
    for index in range(1, len(elements)):
        if elements[index] < elements[index - 1]:
            raise BundleOrderError(
                f"bundle element {index} sorts before element {index - 1}; ES-034 "
                "orders elements by canonical bytes, lexicographic ascending"
            )


def _index_by_record_type(
    records: Iterable[EvidenceRecord],
) -> dict[str, tuple[EvidenceRecord, ...]]:
    index: dict[str, list[EvidenceRecord]] = {}
    for record in records:
        # The only routing statement in this module, and it reads the record.
        index.setdefault(record.record_type, []).append(record)
    return {record_type: tuple(group) for record_type, group in index.items()}


def _require_cardinality(by_type: Mapping[str, tuple[EvidenceRecord, ...]]) -> None:
    attestations = len(by_type.get(REQUIRED_SINGLETON, ()))
    if attestations != 1:
        raise BundleCardinalityError(
            f"bundle carries {attestations} {REQUIRED_SINGLETON} records; ES-034 "
            "requires exactly one"
        )
    boundaries = len(by_type.get(OPTIONAL_SINGLETON, ()))
    if boundaries > 1:
        raise BundleCardinalityError(
            f"bundle carries {boundaries} {OPTIONAL_SINGLETON} records; ES-034 "
            "permits at most one"
        )


def _stream_links(records: Sequence[EvidenceRecord]) -> tuple[StreamLink, ...]:
    by_stream: dict[str, list[EvidenceRecord]] = {}
    for record in records:
        by_stream.setdefault(record.stream_id, []).append(record)

    links: list[StreamLink] = []
    for stream_id, group in sorted(by_stream.items()):
        ordered = sorted(group, key=lambda record: record.sequence)
        for previous, current in zip(ordered, ordered[1:], strict=False):
            if current.sequence == previous.sequence:
                raise BundleCardinalityError(
                    f"stream {stream_id!r} carries two records at sequence "
                    f"{current.sequence} within one bundle"
                )
            if current.sequence != previous.sequence + 1:
                # ES-026 slice: the link across the omission is not checkable
                # from the bundle, so it is reported rather than assumed.
                links.append(
                    StreamLink(
                        stream_id=stream_id,
                        from_sequence=previous.sequence,
                        to_sequence=current.sequence,
                        checked=False,
                    )
                )
                continue
            # ES-006a: the digest of the *complete* previous record, signature
            # included.
            if current.prev_digest != canonical_digest(previous):
                raise BrokenStreamLinkError(
                    f"stream {stream_id!r} sequence {current.sequence} does not "
                    "commit the canonical digest of its predecessor"
                )
            links.append(
                StreamLink(
                    stream_id=stream_id,
                    from_sequence=previous.sequence,
                    to_sequence=current.sequence,
                    checked=True,
                )
            )
    return tuple(links)


def parse_bundle(
    raw: bytes,
    *,
    verification_keys: Mapping[str, RegisteredPublicKey],
) -> Bundle:
    """Parse and verify an ES-034 attestation bundle.

    The order of refusals is itself normative.  Shape, canonical form and
    element order are decided before any signature is examined, because
    ES-S-023 requires a non-canonical bundle to fail naming the canonical form
    rather than a signature.
    """

    decoded = _decode_array(raw)
    canonical = _require_canonical(raw, decoded)

    element_bytes = [canonicalize(element) for element in decoded]
    _require_ascending(element_bytes)

    records: list[EvidenceRecord] = []
    for index, (element, element_canonical) in enumerate(
        zip(decoded, element_bytes, strict=True)
    ):
        if not isinstance(element, dict):
            raise BundleShapeError(
                f"bundle element {index} is not a JSON object; every element is one "
                "complete signed record"
            )
        record = _verify_element(element, element_canonical, verification_keys, index)
        records.append(record)

    by_type = _index_by_record_type(records)
    _require_cardinality(by_type)

    attestation = by_type[REQUIRED_SINGLETON][0]
    assert isinstance(attestation, AttestationWindowRecord)
    # CM-025: the methodology the conclusion was computed under must be one this
    # verifier has rules for, checked before any conclusion is read from it.
    require_published_methodology_version(attestation.body.methodology_version)

    return Bundle(
        records=tuple(records),
        by_type=by_type,
        canonical_bytes=canonical,
        stream_links=_stream_links(records),
    )


def _verify_element(
    element: Mapping[str, Any],
    element_canonical: bytes,
    verification_keys: Mapping[str, RegisteredPublicKey],
    index: int,
) -> EvidenceRecord:
    # Imported here: the verification service depends on the SDK, so a
    # module-level import would close the cycle the other way.
    from services.ingestion.receipts import RegisteredPublicKey as ServiceKey
    from services.ingestion.receipts import verify_canonical_evidence_record

    try:
        # ES-005 closed envelope and the §5 body for this record's own type.
        candidate = validate_record(element)
    except ValueError as exc:
        raise BundleShapeError(f"bundle element {index} is not a valid record: {exc}") from exc

    # ES-035 before any version-dependent rule is applied to the record.
    require_published_schema_version(candidate.schema_version)

    # ES-033 origin dispatch plus, for an AttestationWindow, the mandatory
    # ES-023 counter-signature. Dispatch is on record_type inside this call.
    # The cast reconciles the SDK's structural key protocol with the service's
    # nominal dataclass; only ``namespace`` and ``public_key`` are read.
    verified = verify_canonical_evidence_record(
        element_canonical,
        verification_keys=cast(Mapping[str, ServiceKey], verification_keys),
    )
    assert isinstance(verified, RecordEnvelope)
    return candidate


def assemble_bundle(records: Iterable[RecordEnvelope]) -> bytes:
    """Serialize records into the ES-034 canonical container.

    Ordering is applied here, before assembly, so the same record set produces
    one artifact regardless of the order a producer happened to hold it in —
    which is what QA-008's byte-identical gate compares.
    """

    elements = sorted(canonicalize(record) for record in records)
    return b"[" + b",".join(elements) + b"]"
