"""EV-19 acceptance -- TM-S-004, TM-S-005 and AR-S-004, asserted through the Go verifier.

QA-003 makes the verifier the oracle, and AG-006 says an acceptance test that
reaches into internal state is a unit test. All three scenarios below therefore
run the **compiled Go binary** against a bundle assembled by the Python writer,
and assert on its exit status and its output. Nothing here imports the verifier.

The bundles are built with ``sdk_python.evidence`` -- the writer side. That is
deliberate and is not an AG-017 problem: the point of these scenarios is that an
artifact produced by one implementation is judged by the other. AC-011's ban is
on the two *implementations* sharing code, and no verifier code is imported
here.

As with ES-S-007 the binary is built by the test rather than assumed to exist,
because ``make all`` runs pytest before ``go-test`` and a test that skipped on a
missing binary would be green on exactly the pipeline it guards.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pytest_bdd import given, scenario, then, when

from sdk_python.evidence.canonical import canonicalize
from sdk_python.evidence.schema import (
    AssuranceBoundaryRecord,
    AttestationWindowRecord,
    QualificationRecord,
)
from sdk_python.evidence.signing import counter_sign_attestation, sign_record

REPO = Path(__file__).resolve().parents[2]
VERIFIER_DIR = REPO / "verifier-go"
VECTORS = REPO / "tests" / "vectors" / "vectors-v0.1.json"

EVIDENCE_KEY_ID = "K1"
ISSUER_KEY_ID = "ISSUER1"

# Every scenario is evaluated at a fixed instant. A verifier whose verdict
# depends on the day the suite happens to run is a verifier whose acceptance
# tests expire, and AR-S-004 in particular is a claim about a date comparison,
# not about today.
AS_OF = "2026-10-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Keys and fixture construction
# ---------------------------------------------------------------------------


def _seeds() -> dict[str, bytes]:
    """Private seeds from the normative corpus (ES-029). Test material only."""
    import base64

    corpus = json.loads(VECTORS.read_text(encoding="utf-8"))
    for vector in corpus["vectors"]:
        seeds = vector.get("private_key_seeds")
        if isinstance(seeds, dict) and EVIDENCE_KEY_ID in seeds and ISSUER_KEY_ID in seeds:
            return {
                key_id: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
                for key_id, value in seeds.items()
            }
    raise AssertionError("no vector publishes both fixture seeds")


@pytest.fixture(scope="module")
def keys() -> dict[str, Any]:
    seeds = _seeds()
    evidence_key = Ed25519PrivateKey.from_private_bytes(seeds[EVIDENCE_KEY_ID])
    issuer_key = Ed25519PrivateKey.from_private_bytes(seeds[ISSUER_KEY_ID])
    return {"evidence": evidence_key, "issuer": issuer_key}


@pytest.fixture(scope="module")
def keyring_file(keys: dict[str, Any]) -> Path:
    """Write the keyring the verifier is given, with namespaces stated."""
    import base64

    from cryptography.hazmat.primitives import serialization

    def public_b64(private: Ed25519PrivateKey) -> str:
        raw = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    # testing-qa §10: the namespace a verifier makes a trust decision on must be
    # stated by the input, never defaulted by the harness. That is the defect
    # that hid EV-30's divergence.
    payload = {
        EVIDENCE_KEY_ID: {"namespace": "evidence", "public_key": public_b64(keys["evidence"])},
        ISSUER_KEY_ID: {"namespace": "issuer", "public_key": public_b64(keys["issuer"])},
    }
    path = Path(tempfile.mkdtemp(prefix="ev19-keyring-")) / "keyring.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def go_verifier() -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("no Go toolchain; EV-19 cannot be demonstrated in this environment")
    out = Path(tempfile.mkdtemp(prefix="ev19-")) / "verify"
    result = subprocess.run(  # noqa: S603
        [go, "build", "-o", str(out), "./cmd/verify"],
        cwd=VERIFIER_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"the Go verifier does not build:\n{result.stdout}\n{result.stderr}"
        )
    return out


def _attestation_envelope(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": "01890f47-2f58-7cc0-98c4-000000000064",
        "record_type": "AttestationWindow",
        "schema_version": "1.0.0",
        "tenant_id": "tenant-1",
        "boundary_ref": "boundary-1",
        "stream_id": "attestation-1",
        "sequence": 1,
        "prev_digest": None,
        "source": {"collector": "ev19-acceptance", "version": "0.1.0"},
        "clocks": {"source_time": "2026-09-01T00:00:00.000+00:00"},
        "body": body,
        "signature": {},
    }


def _attestation_body(**overrides: Any) -> dict[str, Any]:
    body = {
        "boundary_ref": "boundary-1",
        "window_start": "2026-07-01T00:00:00.000+00:00",
        "window_end": "2026-07-31T00:00:00.000+00:00",
        "methodology_version": "1.0.0",
        "denominator_class": "C1",
        "population_record_refs": [],
        "coverage_level": "observed",
        "verification_status": "self_computed",
        "coverage_ratio": None,
        "counts": {},
        "gaps": [],
        "assertions": [],
        "exclusions": [],
        "relying_parties": [],
        "validity_from": "2026-09-01T00:00:00.000+00:00",
        "validity_until": "2026-12-01T00:00:00.000+00:00",
        "liability_ref": "terms-1",
        "issued_at": "2026-09-01T00:00:00.000+00:00",
        "issuer": "issuer-1",
        "verifier_version": "0.1.0",
    }
    body.update(overrides)
    return body


def _qualification_body(assigned_class: str, qualified_at: str) -> dict[str, Any]:
    return {
        "action_family": "refund.issue",
        "destination_system": "billing",
        "enumeration": {"api": "list_refunds"},
        "identity_isolation": {"attribute": "service_account"},
        "confirmation": {"api": "get_refund"},
        "temporal": {"authoritative_timestamp_source": "billing"},
        "retention_period": "P90D",
        "mutability": {"deletion_possible": False},
        "assigned_class": assigned_class,
        "class_evidence": "trial-1",
        "trial": {"match_rate": 1},
        "qualified_at": qualified_at,
        "revalidation_cadence": "P90D",
    }


QUALIFICATION_ID = "01890f47-2f58-7cc0-98c4-000000000101"
BOUNDARY_ID = "01890f47-2f58-7cc0-98c4-000000000201"


def _boundary_envelope() -> dict[str, Any]:
    # ES-009 declares a family's qualification on the boundary, so the bundle
    # carries it. Without it the verifier reports the scope as unchecked, which
    # is honest but makes the scenario demonstrate less than it should.
    return {
        "record_id": BOUNDARY_ID,
        "record_type": "AssuranceBoundary",
        "schema_version": "1.0.0",
        "tenant_id": "tenant-1",
        "boundary_ref": "boundary-1",
        "stream_id": "boundary-stream-1",
        "sequence": 1,
        "prev_digest": None,
        "source": {"collector": "ev19-acceptance", "version": "0.1.0"},
        "clocks": {"source_time": "2026-06-01T00:00:00.000+00:00"},
        "body": {
            "boundary_version": "1",
            "tenant": "tenant-1",
            "deployment": "prod",
            "agent_identities": [],
            "action_families": ["refund.issue"],
            "destination_systems": ["billing"],
            "enforcement_points": [],
            "policy_refs": [],
            "window_start": "2026-01-01T00:00:00.000+00:00",
            "window_end": "2027-01-01T00:00:00.000+00:00",
            "collection_modes": ["inline"],
            "fail_behaviour": {"refund.issue": "fail_closed"},
            "qualification_refs": [QUALIFICATION_ID],
        },
        "signature": {},
    }


def _qualification_envelope(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": QUALIFICATION_ID,
        "record_type": "QualificationRecord",
        "schema_version": "1.0.0",
        "tenant_id": "tenant-1",
        "boundary_ref": "boundary-1",
        "stream_id": "qualifications-1",
        "sequence": 1,
        "prev_digest": None,
        "source": {"collector": "ev19-acceptance", "version": "0.1.0"},
        "clocks": {"source_time": "2026-06-01T00:00:00.000+00:00"},
        "body": body,
        "signature": {},
    }


def build_bundle(
    keys: dict[str, Any],
    *,
    attestation_overrides: dict[str, Any] | None = None,
    envelope_overrides: dict[str, Any] | None = None,
    qualification: tuple[str, str] = ("C1", "2026-06-01T00:00:00.000+00:00"),
    extra_records: list[Any] | None = None,
    extra_first: bool = False,
) -> bytes:
    """Assemble a canonical ES-034 bundle: an array of complete signed records."""
    envelope = _attestation_envelope(_attestation_body(**(attestation_overrides or {})))
    envelope.update(envelope_overrides or {})
    attestation = AttestationWindowRecord.model_validate(envelope)
    attestation = sign_record(
        attestation, key_id=EVIDENCE_KEY_ID, private_key=keys["evidence"]
    )
    attestation = counter_sign_attestation(
        attestation, issuer_key_id=ISSUER_KEY_ID, issuer_private_key=keys["issuer"]
    )

    assigned_class, qualified_at = qualification
    qualification_record = QualificationRecord.model_validate(
        _qualification_envelope(_qualification_body(assigned_class, qualified_at))
    )
    qualification_record = sign_record(
        qualification_record, key_id=EVIDENCE_KEY_ID, private_key=keys["evidence"]
    )

    boundary = AssuranceBoundaryRecord.model_validate(_boundary_envelope())
    boundary = sign_record(
        boundary, key_id=EVIDENCE_KEY_ID, private_key=keys["evidence"]
    )

    # exclude_unset matches what the SDK actually signs (see _record_mapping in
    # sdk_python/evidence/signing.py). A plain model_dump would serialize
    # defaults the signature never covered, and the bundle would then be
    # refused for a defect in the fixture rather than in the subject.
    # ES-034: a JSON array of complete signed records, classified by each
    # record's own record_type. exclude_unset matches what the SDK actually
    # signs (see _record_mapping in sdk_python/evidence/signing.py); a plain
    # model_dump would serialize defaults the signature never covered, and the
    # bundle would then be refused for a defect in the fixture rather than in
    # the subject.
    def wire(record: Any) -> Any:
        return json.loads(canonicalize(record.model_dump(mode="json", exclude_unset=True)))

    records = [wire(attestation), wire(boundary), wire(qualification_record)]
    extras = [wire(r) for r in (extra_records or [])]
    if extra_first:
        records = extras + records
    else:
        records = records + extras
    return canonicalize(records)


def run_verifier(
    binary: Path, keyring: Path, bundle_bytes: bytes, *extra: str
) -> subprocess.CompletedProcess[str]:
    path = Path(tempfile.mkdtemp(prefix="ev19-bundle-")) / "bundle.json"
    path.write_bytes(bundle_bytes)
    return subprocess.run(  # noqa: S603
        [
            str(binary),
            "-mode",
            "bundle",
            "-keyring",
            str(keyring),
            "-as-of",
            AS_OF,
            *extra,
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def output_of(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


# ---------------------------------------------------------------------------
# TM-S-004 -- offline verifier reports unchecked revocation (TM-014)
# ---------------------------------------------------------------------------


@scenario("adversarial.feature", "TM-S-004 Offline verifier reports unchecked revocation")
def test_tm_s_004() -> None:
    """Bound by pytest-bdd."""


@given("the verifier is run without network access", target_fixture="network")
def _no_network() -> list[str]:
    # -offline constructs no fetcher at all, so this cannot pass by accident of
    # a connection failure in the test environment: the scenario is about the
    # verifier's conclusion, not about the sandbox's connectivity.
    return ["-offline"]


@when("it validates an attestation bundle", target_fixture="offline_result")
def _validate_offline(
    go_verifier: Path, keyring_file: Path, keys: dict[str, Any], network: list[str]
) -> subprocess.CompletedProcess[str]:
    return run_verifier(go_verifier, keyring_file, build_bundle(keys), *network)


@then("signature and chain verification succeed")
def _signatures_succeed(offline_result: subprocess.CompletedProcess[str]) -> None:
    output = output_of(offline_result)
    assert "REFUSED" not in output, (
        f"the bundle should verify structurally; verifier said:\n{output}"
    )
    # Both ES-023 signers are named, so "signatures verified" is demonstrated
    # rather than inferred from the absence of a complaint.
    assert f"customer key     {EVIDENCE_KEY_ID}" in output, output
    assert f"issuer key       {ISSUER_KEY_ID}" in output, output


@then("the output does not state that the attestation is valid")
def _not_valid(offline_result: subprocess.CompletedProcess[str]) -> None:
    import re

    output = output_of(offline_result)
    # The word as a word. "validity_from" and "validity_until" are field names,
    # not claims, and \b keeps them out of this.
    offending = re.findall(r"\bvalid\b", output, flags=re.IGNORECASE)
    assert not offending, (
        f"an offline verifier used the word 'valid' about the attestation:\n{output}"
    )
    assert "VERDICT unchecked_revocation" in output, output
    # Exit 3 is "I could not check", distinct from exit 1 "this is invalid".
    assert offline_result.returncode == 3, (
        f"exit {offline_result.returncode}; unchecked must not exit 0 (fine) "
        f"or 1 (invalid)\n{output}"
    )


# ---------------------------------------------------------------------------
# TM-S-005 -- retroactive upgrade rejected by verifier (TM-013)
# ---------------------------------------------------------------------------


@scenario("adversarial.feature", "TM-S-005 Retroactive upgrade rejected by verifier")
def test_tm_s_005() -> None:
    """Bound by pytest-bdd."""


@given(
    'a QualificationRecord assigning class C1 dated 2026-09-01',
    target_fixture="qualification",
)
def _qualification_dated_september() -> tuple[str, str]:
    return ("C1", "2026-09-01T00:00:00.000+00:00")


@given(
    "an attestation for a window starting 2026-08-01 claiming class C1",
    target_fixture="attestation_overrides",
)
def _window_starting_august() -> dict[str, Any]:
    return {
        "window_start": "2026-08-01T00:00:00.000+00:00",
        "window_end": "2026-08-31T00:00:00.000+00:00",
        "denominator_class": "C1",
    }


@when("the verifier validates it", target_fixture="verify_result")
def _validate(
    go_verifier: Path,
    keyring_file: Path,
    keys: dict[str, Any],
    request: pytest.FixtureRequest,
) -> subprocess.CompletedProcess[str]:
    # Shared by TM-S-005 and AR-S-004; each supplies whichever fixtures its own
    # Given steps defined.
    overrides = _optional(request, "attestation_overrides") or {}
    envelope = _optional(request, "envelope_overrides") or {}
    qualification = _optional(request, "qualification") or (
        "C1",
        "2026-06-01T00:00:00.000+00:00",
    )
    bundle_bytes = build_bundle(
        keys,
        attestation_overrides=overrides,
        envelope_overrides=envelope,
        qualification=qualification,
    )
    return run_verifier(go_verifier, keyring_file, bundle_bytes, "-offline")


def _optional(request: pytest.FixtureRequest, name: str) -> Any:
    try:
        return request.getfixturevalue(name)
    except pytest.FixtureLookupError:
        return None


@then('verification fails with "qualification postdates window"')
def _fails_with_postdates(verify_result: subprocess.CompletedProcess[str]) -> None:
    output = output_of(verify_result)
    assert verify_result.returncode == 1, (
        f"exit {verify_result.returncode}; a retroactive upgrade must fail "
        f"verification\n{output}"
    )
    assert "VERDICT invalid" in output, output
    assert "qualification postdates window" in output, output


# ---------------------------------------------------------------------------
# AR-S-004 -- expired verifies as expired (AR-009)
# ---------------------------------------------------------------------------


@scenario("attestation.feature", "AR-S-004 Expired verifies as expired")
def test_ar_s_004() -> None:
    """Bound by pytest-bdd."""


@given(
    "an attestation whose validity_until has passed",
    target_fixture="attestation_overrides",
)
def _already_expired() -> dict[str, Any]:
    # AS_OF is 2026-10-01, so this period closed a month before the question
    # was asked.
    return {
        "validity_from": "2026-08-01T00:00:00.000+00:00",
        "validity_until": "2026-09-01T00:00:00.000+00:00",
    }


@then('the result is "expired"')
def _result_expired(verify_result: subprocess.CompletedProcess[str]) -> None:
    output = output_of(verify_result)
    assert "VERDICT expired" in output, output


@then('the result is not "valid"')
def _result_not_valid(verify_result: subprocess.CompletedProcess[str]) -> None:
    import re

    output = output_of(verify_result)
    assert not re.findall(r"\bvalid\b", output, flags=re.IGNORECASE), (
        f"AR-009 forbids expired-but-valid; verifier said:\n{output}"
    )
    assert verify_result.returncode != 0, (
        f"exit {verify_result.returncode}; an expired attestation must not "
        f"exit successfully\n{output}"
    )


# ---------------------------------------------------------------------------
# ES-034 / ES-035 -- the bundle container and the schema registry
# ---------------------------------------------------------------------------


@scenario("evidence.feature", "ES-S-022 A record's role in a bundle comes from the record")
def test_es_s_022() -> None:
    """Bound by pytest-bdd."""


def _coverage_gap_record(keys: dict[str, Any]) -> Any:
    from sdk_python.evidence.schema import CoverageGapRecord

    record = CoverageGapRecord.model_validate(
        {
            "record_id": "01890f47-2f58-7cc0-98c4-000000000301",
            "record_type": "CoverageGap",
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": "gaps-1",
            "sequence": 1,
            "prev_digest": None,
            "source": {"collector": "ev19-acceptance", "version": "0.1.0"},
            "clocks": {"source_time": "2026-07-05T00:00:00.000+00:00"},
            "body": {
                "gap_start": "2026-07-05T00:00:00.000+00:00",
                "gap_end": "2026-07-06T00:00:00.000+00:00",
                "affected_scope": {"families": ["refund.issue"]},
                "cause": "collector_unreachable",
                "detection_source": "collector",
                "exposure": "known",
                "actions_during_gap": None,
            },
            "signature": {},
        }
    )
    return sign_record(record, key_id=EVIDENCE_KEY_ID, private_key=keys["evidence"])


@given(
    "a bundle carrying an attestation and a validly signed CoverageGap",
    target_fixture="gap_bundles",
)
def _bundle_with_gap(keys: dict[str, Any]) -> list[bytes]:
    # The same records in two different orders. If any classification depended
    # on position, these would not agree -- which is the property an array
    # container has and a keyed one does not.
    gap = _coverage_gap_record(keys)
    return [
        build_bundle(keys, extra_records=[gap], extra_first=False),
        build_bundle(keys, extra_records=[gap], extra_first=True),
    ]


@when("the verifier parses the bundle", target_fixture="gap_results")
def _parse_gap_bundles(
    go_verifier: Path, keyring_file: Path, gap_bundles: list[bytes]
) -> list[subprocess.CompletedProcess[str]]:
    return [run_verifier(go_verifier, keyring_file, b, "-offline") for b in gap_bundles]


@then("the CoverageGap is classified as a gap")
def _classified_as_gap(gap_results: list[subprocess.CompletedProcess[str]]) -> None:
    # Observable through the verifier, not by reaching inside it (QA-003): a
    # signed gap the attestation omits from gaps[] is caught by CM-014 gap
    # conservation, and that check only sees records routed to the gap set.
    output = output_of(gap_results[0])
    assert "gap" in output.lower(), output
    assert gap_results[0].returncode != 0, output


@then("it is not classified as a population record")
def _not_classified_as_population(
    gap_results: list[subprocess.CompletedProcess[str]],
) -> None:
    output = output_of(gap_results[0])
    # A gap routed into the population set would go missing from conservation
    # and the bundle would stop being refused for it.
    assert "REFUSED" in output, (
        f"the unlisted signed gap was not caught, which is what happens when a "
        f"CoverageGap is counted as a population:\n{output}"
    )


@then("no position in the container can override its record_type")
def _position_independent(gap_results: list[subprocess.CompletedProcess[str]]) -> None:
    first, last = gap_results
    assert first.returncode == last.returncode, (
        f"the verdict depended on where the gap sat in the container: "
        f"{first.returncode} vs {last.returncode}"
    )
    assert _verdict_line(first) == _verdict_line(last), (
        f"{_verdict_line(first)!r} vs {_verdict_line(last)!r}"
    )


def _verdict_line(result: subprocess.CompletedProcess[str]) -> str:
    for line in output_of(result).splitlines():
        if line.startswith("VERDICT "):
            return line
    return ""


@scenario("evidence.feature", "ES-S-023 A non-canonical bundle is refused")
def test_es_s_023() -> None:
    """Bound by pytest-bdd."""


@given("an attestation bundle that is not RFC 8785 canonical", target_fixture="bad_bundle")
def _non_canonical_bundle(keys: dict[str, Any]) -> bytes:
    return json.dumps(json.loads(build_bundle(keys)), indent=2).encode()


@when("the verifier parses it", target_fixture="parse_result")
def _parse_bad(
    go_verifier: Path, keyring_file: Path, bad_bundle: bytes
) -> subprocess.CompletedProcess[str]:
    return run_verifier(go_verifier, keyring_file, bad_bundle, "-offline")


@then("parsing fails")
def _parse_fails(parse_result: subprocess.CompletedProcess[str]) -> None:
    assert parse_result.returncode == 1, output_of(parse_result)


@then("the failure names the canonical form rather than a signature")
def _names_canonical(parse_result: subprocess.CompletedProcess[str]) -> None:
    output = output_of(parse_result)
    assert "non_canonical" in output, output
    # ES-001's whole point: a producer conformance bug must not be reported as
    # a cryptographic complaint.
    assert "signature.invalid" not in output, output


@scenario("evidence.feature", "ES-S-024 An unpublished schema version is refused")
def test_es_s_024() -> None:
    """Bound by pytest-bdd."""


@given(
    "an attestation whose schema_version is not in the ES-035 registry",
    target_fixture="envelope_overrides",
)
def _unpublished_schema_version() -> dict[str, Any]:
    return {"schema_version": "9.9.9"}


@then("verification fails")
def _verification_fails(verify_result: subprocess.CompletedProcess[str]) -> None:
    assert verify_result.returncode == 1, output_of(verify_result)
    assert "VERDICT invalid" in output_of(verify_result), output_of(verify_result)


@then("the attestation is not verified under another version's rules")
def _not_verified_under_other_rules(
    verify_result: subprocess.CompletedProcess[str],
) -> None:
    assert "schema.version_unsupported" in output_of(verify_result), output_of(
        verify_result
    )


@scenario("coverage.feature", "CM-S-011 An unimplemented methodology version is refused")
def test_cm_s_011() -> None:
    """Bound by pytest-bdd."""


@given(
    "an attestation whose methodology_version is not in the CM-025 registry",
    target_fixture="attestation_overrides",
)
def _unpublished_methodology_version() -> dict[str, Any]:
    return {"methodology_version": "9.9.9"}


@then("the attestation is not recomputed under a different methodology version")
def _not_recomputed(verify_result: subprocess.CompletedProcess[str]) -> None:
    assert "methodology.version_unsupported" in output_of(verify_result), output_of(
        verify_result
    )


# ---------------------------------------------------------------------------
# AR-029 / AR-030 / AR-031 -- the revocation endpoint protocol
# ---------------------------------------------------------------------------


class _Endpoint:
    """A stub issuer revocation endpoint.

    A real HTTP server rather than a fake: AR-029 is a statement about what
    happens on the wire, and a verifier that only ever meets an in-process stub
    has never demonstrated that it can reach an endpoint at all.
    """

    def __init__(self, handler: Any) -> None:
        import http.server
        import threading

        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                status, body = outer.handler(self.path)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self.handler = handler
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _revocation_record(
    keys: dict[str, Any], *, effective_at: str, superseding_ref: str | None
) -> bytes:
    """A signed RevocationRecord, in the issuer namespace ES-033 requires."""
    from sdk_python.evidence.schema import RevocationRecord

    record = RevocationRecord.model_validate(
        {
            "record_id": "01890f47-2f58-7cc0-98c4-0000000000aa",
            "record_type": "RevocationRecord",
            "schema_version": "1.0.0",
            "tenant_id": "tenant-1",
            "boundary_ref": "boundary-1",
            "stream_id": "revocations-1",
            "sequence": 1,
            "prev_digest": None,
            "source": {"collector": "ev19-acceptance", "version": "0.1.0"},
            "clocks": {"source_time": "2026-09-15T00:00:00.000+00:00"},
            "body": {
                "attestation_ref": "01890f47-2f58-7cc0-98c4-000000000064",
                "reason": "discovered computation defect",
                "issuer": "issuer-1",
                "effective_at": effective_at,
                "superseding_ref": superseding_ref,
                "relying_party_notification_status": "sent",
            },
            "signature": {},
        }
    )
    record = sign_record(record, key_id=ISSUER_KEY_ID, private_key=keys["issuer"])
    return canonicalize(record.model_dump(mode="json", exclude_unset=True))


def _check_revocation(
    go_verifier: Path, keyring_file: Path, keys: dict[str, Any], endpoint: _Endpoint
) -> subprocess.CompletedProcess[str]:
    try:
        return run_verifier(
            go_verifier,
            keyring_file,
            build_bundle(keys),
            "-revocation-endpoint",
            endpoint.url,
        )
    finally:
        endpoint.close()


@scenario(
    "attestation.feature",
    "AR-S-009 An answer the verifier cannot authenticate establishes nothing",
)
def test_ar_s_009() -> None:
    """Bound by pytest-bdd."""


@given(
    "a revocation endpoint that does not answer with an authenticated RevocationRecord",
    target_fixture="endpoint",
)
def _unauthenticated_endpoint() -> _Endpoint:
    # A captive portal is the realistic shape of this: HTTP 200, plausible
    # body, nothing the verifier can authenticate.
    return _Endpoint(lambda path: (200, b"<html>sign in to continue</html>"))


@when("the verifier checks revocation for an attestation", target_fixture="revocation_result")
def _check_unauthenticated(
    go_verifier: Path, keyring_file: Path, keys: dict[str, Any], endpoint: _Endpoint
) -> subprocess.CompletedProcess[str]:
    return _check_revocation(go_verifier, keyring_file, keys, endpoint)


@then('revocation_status is reported as "unchecked"')
def _status_unchecked(request: pytest.FixtureRequest) -> None:
    # TM-S-004 and AR-S-009 assert the same sentence about different runs: one
    # offline, one against an endpoint that answers unintelligibly. They share
    # a step definition because they are the same claim -- the verifier learned
    # nothing -- and pytest-bdd matches steps by text, so defining it twice
    # silently shadows the first.
    output = output_of(_result_of(request))
    assert "revocation       unchecked" in output, output


def _result_of(request: pytest.FixtureRequest) -> subprocess.CompletedProcess[str]:
    """Whichever run the current scenario produced."""
    for name in ("revocation_result", "offline_result", "verify_result"):
        result = _optional(request, name)
        if result is not None:
            return result
    raise AssertionError("no verifier run is in scope for this step")


@then('it is not reported as "valid"')
def _status_not_valid(request: pytest.FixtureRequest) -> None:
    output = output_of(_result_of(request))
    assert "revocation       valid" not in output, output


@then('it is not reported as "revoked"')
def _status_not_revoked(request: pytest.FixtureRequest) -> None:
    output = output_of(_result_of(request))
    assert "revocation       revoked" not in output, output


@scenario("attestation.feature", "AR-S-010 Supersession is distinguished from revocation")
def test_ar_s_010() -> None:
    """Bound by pytest-bdd."""


@given(
    "an authenticated RevocationRecord naming a superseding attestation",
    target_fixture="endpoint",
)
def _superseding_endpoint(keys: dict[str, Any]) -> _Endpoint:
    body = _revocation_record(
        keys, effective_at="2026-09-15T00:00:00.000+00:00", superseding_ref="attestation-2"
    )
    return _Endpoint(lambda path: (200, body))


@when("the verifier checks revocation", target_fixture="revocation_result")
def _check_authenticated(
    go_verifier: Path, keyring_file: Path, keys: dict[str, Any], endpoint: _Endpoint
) -> subprocess.CompletedProcess[str]:
    return _check_revocation(go_verifier, keyring_file, keys, endpoint)


@then('revocation_status is reported as "superseded"')
def _status_superseded(revocation_result: subprocess.CompletedProcess[str]) -> None:
    assert "revocation       superseded" in output_of(revocation_result), output_of(
        revocation_result
    )


@then("the superseding attestation is identified")
def _superseding_identified(revocation_result: subprocess.CompletedProcess[str]) -> None:
    assert "attestation-2" in output_of(revocation_result), output_of(revocation_result)


@then('an otherwise identical record with no superseding_ref reports "revoked"')
def _without_superseding_ref_is_revoked(
    go_verifier: Path, keyring_file: Path, keys: dict[str, Any]
) -> None:
    body = _revocation_record(
        keys, effective_at="2026-09-15T00:00:00.000+00:00", superseding_ref=None
    )
    endpoint = _Endpoint(lambda path: (200, body))
    result = _check_revocation(go_verifier, keyring_file, keys, endpoint)
    assert "revocation       revoked" in output_of(result), output_of(result)


@scenario(
    "attestation.feature",
    "AR-S-011 A revocation before its effective date does not revoke",
)
def test_ar_s_011() -> None:
    """Bound by pytest-bdd."""


@given(
    "an authenticated RevocationRecord whose effective_at is later than the evaluation instant",
    target_fixture="endpoint",
)
def _pending_endpoint(keys: dict[str, Any]) -> _Endpoint:
    # AS_OF is 2026-10-01; this takes effect two months later.
    body = _revocation_record(
        keys, effective_at="2026-12-01T00:00:00.000+00:00", superseding_ref=None
    )
    return _Endpoint(lambda path: (200, body))


@then('revocation_status is reported as "valid"')
def _status_valid(revocation_result: subprocess.CompletedProcess[str]) -> None:
    assert "revocation       valid" in output_of(revocation_result), output_of(
        revocation_result
    )


@then("the pending revocation and its effective_at are surfaced")
def _pending_surfaced(revocation_result: subprocess.CompletedProcess[str]) -> None:
    output = output_of(revocation_result)
    assert "not_yet_effective" in output, output
    assert "2026-12-01" in output, output


@then("the evaluation instant appears in the output")
def _instant_surfaced(revocation_result: subprocess.CompletedProcess[str]) -> None:
    assert f"evaluated at     {AS_OF}" in output_of(revocation_result), output_of(
        revocation_result
    )
