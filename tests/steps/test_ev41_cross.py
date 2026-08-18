"""Cross-implementation acceptance for EV-41's assertion routing decision."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pytest_bdd import given, scenario, then, when

from services.ingestion.receipts import RegisteredPublicKey
from services.verification.bundle import verify_attestation_bundle

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "tests" / "vectors" / "vectors-v0.1.json"


@scenario("evidence.feature", "ES-S-025 Assertion routing agrees across implementations")
def test_es_s_025_assertion_routing_agrees() -> None:
    """ES-036, AR-003."""


@pytest.fixture(scope="module")
def ev41_go_verifier(tmp_path_factory: pytest.TempPathFactory) -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.fail("Go is required for the EV-41 cross-implementation gate")
    output = tmp_path_factory.mktemp("ev41-go") / "verify"
    completed = subprocess.run(  # noqa: S603 - resolved Go tool, fixed build target
        [go, "build", "-o", str(output), "./cmd/verify"],
        cwd=REPO / "verifier-go",
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return output


@given(
    "a signed bundle carrying an assertion_id outside the catalogue",
    target_fixture="assertion_vector",
)
def _assertion_vector() -> dict[str, object]:
    document = json.loads(CORPUS.read_text(encoding="utf-8"))
    return next(
        vector
        for vector in document["vectors"]
        if vector["id"] == "reject-assertion-outside-catalogue"
    )


@when(
    "the same bundle bytes are verified by the Python and Go entry points",
    target_fixture="cross_results",
)
def _verify_both(
    assertion_vector: dict[str, object],
    ev41_go_verifier: Path,
    tmp_path: Path,
) -> tuple[tuple[str, ...], subprocess.CompletedProcess[str]]:
    encoded_keys = assertion_vector["verification_keys"]
    assert isinstance(encoded_keys, dict)
    keys = {
        key_id: RegisteredPublicKey(
            namespace=value["namespace"],
            public_key=Ed25519PublicKey.from_public_bytes(
                base64.urlsafe_b64decode(
                    value["public_key"] + "=" * (-len(value["public_key"]) % 4)
                )
            ),
        )
        for key_id, value in encoded_keys.items()
    }
    wire = bytes.fromhex(str(assertion_vector["bundle_utf8_hex"]))
    python_result = verify_attestation_bundle(
        wire,
        verification_keys=keys,
        evaluated_at=str(assertion_vector["evaluated_at"]),
    )

    bundle_path = tmp_path / "bundle.json"
    keyring_path = tmp_path / "keyring.json"
    bundle_path.write_bytes(wire)
    keyring_path.write_text(json.dumps(encoded_keys), encoding="utf-8")
    go_result = subprocess.run(  # noqa: S603 - binary built by the fixture above
        [
            str(ev41_go_verifier),
            "-mode",
            "bundle",
            "-offline",
            "-as-of",
            str(assertion_vector["evaluated_at"]),
            "-keyring",
            str(keyring_path),
            str(bundle_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return python_result.error_codes, go_result


@then("both refuse with assertion.outside_catalogue")
def _both_refuse(cross_results: tuple[tuple[str, ...], subprocess.CompletedProcess[str]]) -> None:
    python_codes, go_result = cross_results
    assert python_codes == ("assertion.outside_catalogue",)
    assert go_result.returncode == 1
    assert "assertion.outside_catalogue" in go_result.stderr
