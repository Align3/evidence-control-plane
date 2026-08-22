"""EV-42's scoped qualification-cadence grammar amendment."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from services.admin.qualification import QualificationError, add_iso8601_duration


@pytest.mark.parametrize(
    ("duration", "expected"),
    [
        ("PT1H", datetime(2026, 8, 18, 13, 0, tzinfo=UTC)),
        ("P1D", datetime(2026, 8, 19, 12, 0, tzinfo=UTC)),
        ("P1DT2H30M15.5S", datetime(2026, 8, 19, 14, 30, 15, 500_000, tzinfo=UTC)),
        ("P2W", datetime(2026, 9, 1, 12, 0, tzinfo=UTC)),
        ("P1M", datetime(2026, 9, 18, 12, 0, tzinfo=UTC)),
        ("P1Y", datetime(2027, 8, 18, 12, 0, tzinfo=UTC)),
    ],
)
def test_revalidation_cadence_accepts_iso_8601_date_and_time_forms(
    duration: str, expected: datetime
) -> None:
    assert (
        add_iso8601_duration(
            datetime(2026, 8, 18, 12, 0, tzinfo=UTC),
            duration,
            label="revalidation_cadence",
        )
        == expected
    )


def test_calendar_month_cadence_clamps_to_the_last_real_day() -> None:
    assert add_iso8601_duration(
        datetime(2027, 1, 31, 12, 0, tzinfo=UTC),
        "P1M",
        label="revalidation_cadence",
    ) == datetime(2027, 2, 28, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "duration",
    ["", "P", "PT", "P0D", "PT0S", "P-1D", "1H", "P1W1D", "P1.5M"],
)
def test_invalid_or_nonpositive_cadence_is_refused(duration: str) -> None:
    with pytest.raises(QualificationError, match="revalidation_cadence"):
        add_iso8601_duration(
            datetime(2026, 8, 18, 12, 0, tzinfo=UTC),
            duration,
            label="revalidation_cadence",
        )


def test_duration_requires_an_aware_start_instant() -> None:
    with pytest.raises(QualificationError, match="timezone-aware"):
        add_iso8601_duration(
            datetime(2026, 8, 18, 12, 0),
            "PT1H",
            label="revalidation_cadence",
        )
