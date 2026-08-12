"""Locally signed CoverageGap emission (IN-011).

This module imports no transport and must keep it that way. The requirement is
not "emit a gap when convenient" — it is that the evidence of our unavailability
survives our unavailability. Any hosted dependency on this path, including a
"just to fetch the current sequence" call, reintroduces the failure the
requirement exists to prevent: our outage erasing the record of our outage.

`tests/unit/test_client_gaps.py` asserts the import closure of this module
contains nothing that can open a socket, so the property is enforced rather
than merely intended.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from sdk_python.client.buffer import BufferedRecord
from sdk_python.client.identity import SigningIdentity
from sdk_python.client.records import build_envelope, rfc3339, sign_locally

GapCause = Literal[
    "collector_unreachable",
    "fail_open",
    "sequence_break",
    "denominator_unavailable",
    "clock_skew",
    "key_discontinuity",
]

#: What the SDK can honestly say about how much happened during the gap.
#: "known" is only correct when the client counted the affected actions itself,
#: which it can for buffer exhaustion and cannot for an unbounded outage.
Exposure = Literal["known", "estimated_bounds", "unknown"]


def build_coverage_gap(
    *,
    identity: SigningIdentity,
    tenant_id: str,
    boundary_ref: str,
    collector_id: str,
    deployment: str,
    stream_id: str,
    sequence: int,
    prev_digest: str | None,
    gap_start: datetime,
    gap_end: datetime,
    affected_scope: Mapping[str, Any],
    cause: GapCause,
    exposure: Exposure,
    actions_during_gap: int | None,
    detection_source: str = "python-sdk-client",
) -> tuple[BufferedRecord, str]:
    """Construct and locally sign a CoverageGap. No network, by construction."""

    if gap_end < gap_start:
        raise ValueError("a coverage gap cannot end before it starts")
    envelope = build_envelope(
        record_type="CoverageGap",
        body={
            "gap_start": rfc3339(gap_start),
            "gap_end": rfc3339(gap_end),
            "affected_scope": dict(affected_scope),
            "cause": cause,
            "detection_source": detection_source,
            "exposure": exposure,
            # Required but nullable: an explicit null is a claim that the count
            # is unknown, which is different from omitting the member.
            "actions_during_gap": actions_during_gap,
        },
        tenant_id=tenant_id,
        boundary_ref=boundary_ref,
        collector_id=collector_id,
        deployment=deployment,
        stream_id=stream_id,
        sequence=sequence,
        prev_digest=prev_digest,
        source_time=gap_end,
    )
    return sign_locally(envelope, identity)
