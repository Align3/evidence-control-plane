"""Negative-first EV-41 tests for Python attestation-bundle verification."""

from __future__ import annotations

import json

import pytest

from sdk_python.evidence.bundle import BundleShapeError, parse_bundle
from sdk_python.evidence.canonical import canonicalize
from services.verification.bundle import (
    RevocationResponse,
    fetch_revocation,
    verify_attestation_bundle,
)
from tests.ev41_bundle_support import (
    build_bundle,
    coverage_gap_record,
    decode_bundle,
    resign_attestation,
    revocation_record,
    verification_keys,
)

AS_OF = "2026-10-01T00:00:00.000Z"


def verify(fixture: object, **kwargs: object):
    wire = fixture.wire  # type: ignore[attr-defined]
    return verify_attestation_bundle(
        wire,
        verification_keys=verification_keys(),
        evaluated_at=AS_OF,
        **kwargs,  # type: ignore[arg-type]
    )


def test_es_034_refuses_non_array_container_before_signature_checks() -> None:
    with pytest.raises(BundleShapeError, match="array"):
        parse_bundle(canonicalize({"records": []}), verification_keys={})


def test_es_034_refuses_noncanonical_container_before_signature_checks() -> None:
    fixture = build_bundle()
    noncanonical = json.dumps(json.loads(fixture.wire), indent=2).encode()
    result = verify_attestation_bundle(noncanonical, verification_keys={}, evaluated_at=AS_OF)
    assert result.error_codes == ("bundle.non_canonical",)


def test_es_034_refuses_element_order_mutation() -> None:
    fixture = build_bundle()
    reversed_records = list(reversed(decode_bundle(fixture)))
    result = verify_attestation_bundle(
        canonicalize(reversed_records),
        verification_keys=verification_keys(),
        evaluated_at=AS_OF,
    )
    assert result.error_codes == ("bundle.element_order",)


def test_es_034_classifies_by_record_type_and_refuses_unreported_signed_gap() -> None:
    result = verify(build_bundle(gap_record=coverage_gap_record()))
    assert result.error_codes == ("coverage.gap_unreported",)


def test_cm_014_gap_match_includes_affected_scope() -> None:
    announced = {
        "gap_start": "2026-08-10T00:00:00.000Z",
        "gap_end": "2026-08-11T00:00:00.000Z",
        "cause": "outage",
        "affected_scope": {"action_family": "different.scope"},
    }
    result = verify(
        build_bundle(gap_record=coverage_gap_record(), announced_gaps=[announced])
    )
    assert result.error_codes == ("coverage.gap_unreported",)


@pytest.mark.parametrize("version", ["2.0.0", "9.9.9"])
def test_es_035_refuses_reserved_and_absent_schema_versions(version: str) -> None:
    result = verify(build_bundle(schema_version=version))
    assert result.error_codes == ("schema.version_unsupported",)


def test_cm_025_refuses_unpublished_methodology_without_fallback() -> None:
    result = verify(build_bundle(methodology_version="9.9.9"))
    assert result.error_codes == ("methodology.version_unsupported",)


def test_es_017_excludes_out_of_scope_and_uses_fixed_four_places() -> None:
    result = verify(build_bundle(population_count=4, matched=1, out_of_scope=1, ratio="0.3333"))
    assert result.accepted
    assert result.coverage_ratio == "0.3333"


def test_es_017_truncates_instead_of_rounding_half_up() -> None:
    result = verify(build_bundle(population_count=3, matched=2, out_of_scope=0, ratio="0.6666"))
    assert result.accepted
    assert result.coverage_ratio == "0.6666"


def test_es_017_refuses_the_nearby_round_half_up_result() -> None:
    result = verify(build_bundle(population_count=3, matched=2, out_of_scope=0, ratio="0.6667"))
    assert result.error_codes == ("coverage.ratio_mismatch",)


@pytest.mark.parametrize(
    ("kwargs", "declared"),
    [
        ({"denominator_class": "C4", "coverage_level": "observed"}, "0.2500"),
        ({"pagination_complete": False}, "0.3333"),
        ({"result_cap_hit": True}, "0.3333"),
        ({"population_count": 1, "matched": 0, "out_of_scope": 1}, "0.0000"),
    ],
)
def test_ratio_withholding_rules_refuse_a_number(kwargs: dict[str, object], declared: str) -> None:
    fixture = build_bundle(**kwargs, ratio=declared)  # type: ignore[arg-type]
    assert verify(fixture).error_codes == ("coverage.ratio_mismatch",)


def test_cm_012_refuses_counts_that_do_not_conserve_population() -> None:
    fixture = resign_attestation(
        build_bundle(), lambda raw: raw["body"]["counts"].__setitem__("ambiguous", 1)
    )
    assert verify(fixture).error_codes == ("coverage.count_conservation",)


def test_ar_003_refuses_off_catalogue_assertion_even_when_resigned() -> None:
    assertion = {"assertion_id": "A-11", "scope": {}, "counts": {}}
    result = verify(build_bundle(assertions=[assertion]))
    assert result.error_codes == ("assertion.outside_catalogue",)


def test_ar_003_catalogue_id_does_not_imply_unpublished_payload_validation() -> None:
    assertion = {"assertion_id": "A-01", "caller_defined_claim": "anything"}
    result = verify(
        build_bundle(assertions=[assertion]),
        revocation_response=RevocationResponse(404),
    )
    assert result.verdict == "unchecked"
    assert result.unchecked == ("assertion.payload:A-01",)


def test_cm_008_refuses_level_above_denominator_class_ceiling() -> None:
    result = verify(
        build_bundle(
            denominator_class="C4",
            coverage_level="reconciled",
            ratio=None,
        )
    )
    assert result.error_codes == ("coverage.level_exceeds_class",)


def test_tm_013_refuses_qualification_at_exact_window_boundary() -> None:
    result = verify(build_bundle(qualified_at="2026-08-01T00:00:00.000Z"))
    assert result.error_codes == ("qualification.postdates_window",)


def test_ar_009_expired_is_not_valid_with_warning() -> None:
    result = verify(build_bundle(validity_until="2026-09-30T00:00:00.000Z"))
    assert result.accepted
    assert result.verdict == "expired"
    assert result.verdict != "valid"


def test_tm_014_offline_is_unchecked_and_never_valid() -> None:
    result = verify(build_bundle())
    assert result.accepted
    assert result.verdict == "unchecked_revocation"
    assert result.revocation_status == "unchecked"


def test_ar_029_only_404_establishes_clean_absence() -> None:
    valid = verify(build_bundle(), revocation_response=RevocationResponse(404))
    server_error = verify(build_bundle(), revocation_response=RevocationResponse(500))
    assert valid.verdict == "valid"
    assert valid.revocation_status == "valid"
    assert server_error.verdict == "unchecked_revocation"


def test_ar_029_wrong_attestation_and_invalid_body_establish_nothing() -> None:
    wrong = RevocationResponse(
        200,
        revocation_record(
            effective_at="2026-09-01T00:00:00.000Z",
            superseding_ref=None,
            attestation_ref="01890f47-2f58-7cc0-98c4-000000000999",
        ),
    )
    malformed = RevocationResponse(200, b"<html>captive portal</html>")
    assert verify(build_bundle(), revocation_response=wrong).revocation_status == "unchecked"
    assert verify(build_bundle(), revocation_response=malformed).revocation_status == "unchecked"


def test_ar_030_supersession_is_not_plain_revocation() -> None:
    response = RevocationResponse(
        200,
        revocation_record(
            effective_at="2026-09-01T00:00:00.000Z",
            superseding_ref="attestation-2",
        ),
    )
    result = verify(build_bundle(), revocation_response=response)
    assert result.verdict == "superseded"
    assert result.superseding_ref == "attestation-2"


def test_ar_031_compares_parsed_instants_and_exact_boundary() -> None:
    same_instant = RevocationResponse(
        200,
        revocation_record(effective_at="2026-10-01T01:00:00.000+01:00", superseding_ref=None),
    )
    pending = RevocationResponse(
        200,
        revocation_record(effective_at="2026-10-01T00:00:00.001Z", superseding_ref=None),
    )
    assert verify(build_bundle(), revocation_response=same_instant).verdict == "revoked"
    pending_result = verify(build_bundle(), revocation_response=pending)
    assert pending_result.verdict == "valid"
    assert pending_result.pending_revocation_effective_at == "2026-10-01T00:00:00.001Z"


def test_ar_029_fetch_path_is_exact_and_network_failure_is_unchecked() -> None:
    seen: list[str] = []

    def opener(url: str) -> RevocationResponse:
        seen.append(url)
        return RevocationResponse(404)

    response = fetch_revocation("https://issuer.example/", "attestation-1", opener=opener)
    assert response == RevocationResponse(404)
    assert seen == ["https://issuer.example/revocations/attestation-1"]

    def offline(url: str) -> RevocationResponse:
        raise OSError(url)

    assert fetch_revocation("https://issuer.example", "attestation-1", opener=offline) is None
