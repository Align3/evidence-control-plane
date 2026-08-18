"""Exact instant comparison for RFC 3339 timestamps (AR-031).

AR-031 requires that ``effective_at`` and the verifier's evaluation instant be
compared *as instants* and never as strings.  ES-002 allows an explicit offset
and any precision from milliseconds upward, so ``2026-10-01T10:00:00.000Z`` and
``2026-10-01T11:00:00.000+01:00`` denote one instant and two strings, and a
lexical comparison ranks them apart.

The comparison is integer nanoseconds since the epoch.  No float is involved,
because a boundary that AR-031 pins exactly must not move with binary rounding.
A timestamp carrying more fractional digits than nanoseconds is refused rather
than truncated: truncating would silently move a value across the boundary the
requirement pins, and ES-002a already establishes refusal as the response to a
value this corpus cannot represent exactly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

_RFC3339 = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[Tt](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"\.(?P<fraction>\d+)"
    r"(?:[Zz]|(?P<sign>[+-])(?P<offset_hour>\d{2}):(?P<offset_minute>\d{2}))$"
)

NANOSECOND_DIGITS: Final = 9


class TimestampError(ValueError):
    """A timestamp is not an RFC 3339 instant this verifier can compare exactly."""


@dataclass(frozen=True, slots=True)
class Instant:
    """A point in time, comparable independently of how it was written.

    Ordering is defined only on ``epoch_nanoseconds``.  A generated comparison
    including ``text`` would rank two spellings of one instant apart, which is
    exactly the comparison AR-031 forbids, so the operators are written out.
    """

    epoch_nanoseconds: int
    text: str = ""

    def __lt__(self, other: Instant) -> bool:
        return self.epoch_nanoseconds < other.epoch_nanoseconds

    def __le__(self, other: Instant) -> bool:
        return self.epoch_nanoseconds <= other.epoch_nanoseconds

    def __gt__(self, other: Instant) -> bool:
        return self.epoch_nanoseconds > other.epoch_nanoseconds

    def __ge__(self, other: Instant) -> bool:
        return self.epoch_nanoseconds >= other.epoch_nanoseconds

    def same_instant_as(self, other: Instant) -> bool:
        return self.epoch_nanoseconds == other.epoch_nanoseconds


def parse_instant(value: object) -> Instant:
    """Parse an RFC 3339 timestamp to an exact instant, or refuse it."""

    if not isinstance(value, str):
        raise TimestampError("timestamp must be an RFC 3339 string")
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise TimestampError(
            f"timestamp {value!r} is not RFC 3339 with an explicit offset and "
            "at least millisecond precision (ES-002)"
        )

    fraction = match.group("fraction")
    if len(fraction) < 3:
        raise TimestampError("ES-002 requires at least millisecond precision")
    if len(fraction) > NANOSECOND_DIGITS:
        raise TimestampError(
            "timestamp carries finer than nanosecond precision; refused rather "
            "than truncated, because truncation can move a value across the "
            "AR-031 effective-date boundary"
        )
    nanoseconds = int(fraction.ljust(NANOSECOND_DIGITS, "0"))

    second = int(match.group("second"))
    if second == 60:
        raise TimestampError(
            "leap-second timestamps are refused because this verifier has no "
            "authoritative leap-second table"
        )
    if int(match.group("hour")) > 23 or int(match.group("minute")) > 59 or second > 59:
        raise TimestampError(f"timestamp {value!r} contains an invalid time")

    try:
        naive = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            second,
            tzinfo=UTC,
        )
    except ValueError as exc:
        raise TimestampError(f"timestamp {value!r} contains an invalid date") from exc

    if match.group("sign") is not None:
        offset_hour = int(match.group("offset_hour"))
        offset_minute = int(match.group("offset_minute"))
        if offset_hour > 23 or offset_minute > 59:
            raise TimestampError(f"timestamp {value!r} contains an invalid UTC offset")
        offset = timedelta(hours=offset_hour, minutes=offset_minute)
        naive -= offset if match.group("sign") == "+" else -offset

    epoch_seconds = int(naive.timestamp())
    return Instant(epoch_nanoseconds=epoch_seconds * 10**9 + nanoseconds, text=value)
