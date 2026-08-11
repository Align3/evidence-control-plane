"""Acceptance for ES-033 record-origin namespace dispatch."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pytest_bdd import given, scenario, then, when

from sdk_python.evidence.canonical import canonicalize
from services.ingestion.receipts import (
    RegisteredPublicKey,
    verify_canonical_evidence_record,
)

REPO = Path(__file__).resolve().parents[2]
VECTOR_PATH = REPO / "tests" / "vectors" / "vectors-v0.1.json"
VERIFIER_DIR = REPO / "verifier-go"
ORIGIN_VECTOR_IDS = {
    "accept-populationrecord-signed-by-issuer-key",
    "reject-populationrecord-signed-by-evidence-key",
    "accept-externalconfirmation-signed-by-issuer-key",
    "reject-externalconfirmation-signed-by-evidence-key",
    "verify-customer-and-issuer-signatures",
    "adversarial-reject-attestation-without-issuer-signature",
}


@scenario("evidence.feature", "ES-S-019 Record origin fixes the signer namespace")
def test_es_s_019() -> None:
    """Bound by pytest-bdd."""


@scenario("security.feature", "SE-S-008 Deployment location cannot change observation origin")
def test_se_s_008() -> None:
    """Bound by pytest-bdd."""


@dataclass(frozen=True)
class VerificationResult:
    vector_id: str
    expected_acceptance: bool
    python_accepted: bool
    go_accepted: bool
    typescript_accepted: bool
    python_error: str
    go_error: str
    typescript_error: str


@pytest.fixture(scope="module")
def origin_go_verifier() -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("no Go toolchain; origin agreement cannot be demonstrated")
    output = Path(tempfile.mkdtemp(prefix="es-s-019-")) / "verify"
    built = subprocess.run(  # noqa: S603
        [go, "build", "-buildvcs=false", "-o", str(output), "./cmd/verify"],
        cwd=VERIFIER_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if built.returncode != 0:
        raise AssertionError(f"Go verifier build failed:\n{built.stdout}\n{built.stderr}")
    return output


@pytest.fixture(scope="module")
def origin_typescript_runtime() -> str:
    node = shutil.which("node")
    if node is None:
        pytest.skip("no Node runtime; TypeScript origin agreement cannot be demonstrated")
    return node


def _vectors(*, accepted: bool | None = None) -> list[dict[str, Any]]:
    document = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    vectors = [*document["vectors"], *document["adversarial_vectors"]]
    selected = [vector for vector in vectors if vector["id"] in ORIGIN_VECTOR_IDS]
    if accepted is not None:
        selected = [
            vector for vector in selected if vector["expected"]["accepted"] is accepted
        ]
    return selected


def _record(vector: dict[str, Any]) -> dict[str, Any]:
    if "record" in vector:
        return vector["record"]
    return json.loads(bytes.fromhex(vector["received_wire_utf8_hex"]))


@given(
    "a PopulationRecord and ExternalConfirmation signed by an evidence-namespace key",
    target_fixture="origin_vectors",
)
def _evidence_and_issuer_origin_vectors() -> list[dict[str, Any]]:
    return _vectors()


@given("equivalent records signed by an issuer-namespace key")
def _issuer_controls_present(origin_vectors: list[dict[str, Any]]) -> None:
    accepted_observations = [
        vector
        for vector in origin_vectors
        if vector["expected"]["accepted"]
        and _record(vector)["record_type"] != "AttestationWindow"
    ]
    assert len(accepted_observations) == 2


@given("an AttestationWindow with both required proofs and one with its issuer proof removed")
def _attestation_controls_present(origin_vectors: list[dict[str, Any]]) -> None:
    attestations = [
        vector
        for vector in origin_vectors
        if _record(vector)["record_type"] == "AttestationWindow"
    ]
    assert len(attestations) == 2
    assert {vector["expected"]["accepted"] for vector in attestations} == {False, True}


@given(
    "a P2 connector that can reach a customer evidence key but not an issuer key",
    target_fixture="fallback_vectors",
)
def _p2_without_issuer_key() -> list[dict[str, Any]]:
    return [
        vector
        for vector in _vectors(accepted=False)
        if _record(vector)["record_type"]
        in {"PopulationRecord", "ExternalConfirmation"}
    ]


def _registered_keys(raw: dict[str, dict[str, str]]) -> dict[str, RegisteredPublicKey]:
    return {
        key_id: RegisteredPublicKey(
            namespace=value["namespace"],
            public_key=Ed25519PublicKey.from_public_bytes(
                base64.urlsafe_b64decode(
                    value["public_key"] + "=" * (-len(value["public_key"]) % 4)
                )
            ),
        )
        for key_id, value in raw.items()
    }


def _verify_all(
    vectors: list[dict[str, Any]], binary: Path, node: str
) -> list[VerificationResult]:
    results: list[VerificationResult] = []
    for vector in vectors:
        wire = (
            canonicalize(vector["record"])
            if "record" in vector
            else bytes.fromhex(vector["received_wire_utf8_hex"])
        )
        python_accepted = True
        python_error = ""
        try:
            verify_canonical_evidence_record(
                wire, verification_keys=_registered_keys(vector["verification_keys"])
            )
        except Exception as error:  # noqa: BLE001 - result is compared below
            python_accepted = False
            python_error = str(error)

        with tempfile.TemporaryDirectory(prefix="origin-vector-") as directory:
            root = Path(directory)
            record_path = root / "record.json"
            keyring_path = root / "keyring.json"
            record_path.write_bytes(wire)
            keyring_path.write_text(
                json.dumps(vector["verification_keys"]), encoding="utf-8"
            )
            completed = subprocess.run(  # noqa: S603
                [
                    str(binary),
                    "-mode",
                    "record",
                    "-keyring",
                    str(keyring_path),
                    str(record_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        typescript = subprocess.run(  # noqa: S603
            [
                node,
                "--experimental-strip-types",
                "--input-type=module",
                "-e",
                (
                    'import { verifyCanonicalEvidenceRecordWire } from '
                    '"./sdk_typescript/src/index.ts";'
                    'import { readFileSync } from "node:fs";'
                    'const input=JSON.parse(readFileSync(0,"utf8"));'
                    'try { verifyCanonicalEvidenceRecordWire('
                    'Buffer.from(input.wire,"hex"),input.keyring);'
                    'console.log(JSON.stringify({accepted:true})); }'
                    'catch (error) { console.log(JSON.stringify({accepted:false,'
                    'error_code:error.code,message:error.message})); }'
                ),
            ],
            cwd=REPO,
            input=json.dumps(
                {"wire": wire.hex(), "keyring": vector["verification_keys"]}
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        if typescript.returncode != 0:
            raise AssertionError(
                "TypeScript verifier failed to run:\n"
                f"{typescript.stdout}\n{typescript.stderr}"
            )
        typescript_result = json.loads(typescript.stdout)
        results.append(
            VerificationResult(
                vector_id=vector["id"],
                expected_acceptance=vector["expected"]["accepted"],
                python_accepted=python_accepted,
                go_accepted=completed.returncode == 0,
                typescript_accepted=typescript_result["accepted"],
                python_error=python_error,
                go_error=completed.stderr,
                typescript_error=typescript_result.get("error_code", ""),
            )
        )
    return results


@when(
    "Python, Go, and TypeScript verify each complete record under the same registered keyring",
    target_fixture="origin_results",
)
def _verify_origin_vectors(
    origin_vectors: list[dict[str, Any]],
    origin_go_verifier: Path,
    origin_typescript_runtime: str,
) -> list[VerificationResult]:
    return _verify_all(origin_vectors, origin_go_verifier, origin_typescript_runtime)


@when(
    "it attempts to produce a PopulationRecord or ExternalConfirmation",
    target_fixture="fallback_results",
)
def _attempt_evidence_fallback(
    fallback_vectors: list[dict[str, Any]],
    origin_go_verifier: Path,
    origin_typescript_runtime: str,
) -> list[VerificationResult]:
    return _verify_all(fallback_vectors, origin_go_verifier, origin_typescript_runtime)


@then('both evidence-signed issuer observations fail with "key namespace mismatch"')
def _evidence_signed_refused(origin_results: list[VerificationResult]) -> None:
    refused = [
        result
        for result in origin_results
        if not result.expected_acceptance and "attestation" not in result.vector_id
    ]
    assert len(refused) == 2
    assert all(
        not result.python_accepted
        and not result.go_accepted
        and not result.typescript_accepted
        for result in refused
    )
    assert all("namespace" in result.python_error for result in refused)
    assert all("key.namespace_mismatch" in result.go_error for result in refused)
    assert all(result.typescript_error == "key.namespace_mismatch" for result in refused)


@then("both issuer-signed issuer observations verify")
def _issuer_signed_accepted(origin_results: list[VerificationResult]) -> None:
    accepted = [
        result
        for result in origin_results
        if result.expected_acceptance
        and "attestation" not in result.vector_id
        and "customer-and-issuer" not in result.vector_id
    ]
    assert len(accepted) == 2
    assert all(
        result.python_accepted and result.go_accepted and result.typescript_accepted
        for result in accepted
    )


@then("only the complete two-proof AttestationWindow verifies")
def _attestation_origin_proofs(origin_results: list[VerificationResult]) -> None:
    attestations = [
        result
        for result in origin_results
        if "attestation" in result.vector_id or "customer-and-issuer" in result.vector_id
    ]
    assert len(attestations) == 2
    assert all(
        result.python_accepted == result.expected_acceptance
        and result.go_accepted == result.expected_acceptance
        and result.typescript_accepted == result.expected_acceptance
        for result in attestations
    )


@then("no issuer observation is emitted")
def _no_fallback_output(fallback_results: list[VerificationResult]) -> None:
    assert fallback_results
    assert all(
        not result.python_accepted
        and not result.go_accepted
        and not result.typescript_accepted
        for result in fallback_results
    )


@then("the evidence key is not accepted as a fallback signer")
def _no_evidence_fallback(fallback_results: list[VerificationResult]) -> None:
    assert all("namespace" in result.python_error for result in fallback_results)
    assert all("key.namespace_mismatch" in result.go_error for result in fallback_results)
    assert all(
        result.typescript_error == "key.namespace_mismatch"
        for result in fallback_results
    )
