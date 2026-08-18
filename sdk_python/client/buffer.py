"""Bounded local buffer (IN-010).

The buffer stores the signed canonical bytes verbatim. It does not store a
record object that gets re-serialized on flush, because re-serializing invites
a later change to canonicalisation or field ordering to alter bytes a signature
already covers. What was signed is what is sent.

The bound is enforced by refusing the *new* record, never by evicting an old
one. This is not a preference between two workable designs. Evicting the oldest
entry destroys the record at sequence 1, and with it the anchor every later
record's `prev_digest` chains back to: what survives the outage is then a
stream that starts mid-chain and cannot be verified at all. Refusing the new
record instead costs exactly one un-captured action, which a `CoverageGap`
accounts for honestly, and leaves everything already anchored intact.

So the bound applies to admission, and the loss it causes is always at the
newest edge of the stream where a gap marker can describe it.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass


class BufferFullError(RuntimeError):
    """The bound is reached. The new record cannot be admitted."""


@dataclass(frozen=True, slots=True)
class BufferedRecord:
    """One locally signed record awaiting submission.

    `canonical_bytes` are the complete signed record as it will go on the wire.
    `signed_at` is the record's own `clocks.source_time`, retained so a flush
    can be asserted not to have re-timestamped it (IN-010, IN-012).
    """

    record_id: str
    record_type: str
    stream_id: str
    sequence: int
    signed_at: str
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if not self.canonical_bytes:
            raise ValueError("a buffered record must carry its signed bytes")
        if self.sequence < 1:
            raise ValueError("sequence starts at 1")


class BoundedBuffer:
    """FIFO with a hard bound and no silent eviction."""

    def __init__(self, bound: int) -> None:
        if bound < 1:
            raise ValueError("buffer bound must be at least 1")
        self._bound = bound
        self._items: deque[BufferedRecord] = deque()
        self._refused = 0

    @property
    def bound(self) -> int:
        return self._bound

    @property
    def refused(self) -> int:
        """New records the client could not capture because the bound was reached.

        Counts silent loss only: emissions the caller was *not* told about,
        which under IN-013 means fail-open families. A fail-closed refusal
        raises, so the caller already knows the action has no evidence and
        nothing was lost behind its back.
        """

        return self._refused

    def is_full(self) -> bool:
        return len(self._items) >= self._bound

    def append(self, record: BufferedRecord) -> None:
        """Accept a record, or refuse because the bound is reached."""

        if self.is_full():
            raise BufferFullError(
                f"local buffer bound of {self._bound} reached; "
                "the new record cannot be admitted and a CoverageGap must "
                "account for it"
            )
        self._items.append(record)

    def record_refusal(self) -> None:
        """Count one new record lost to the bound without the caller knowing."""

        self._refused += 1

    def drain(self) -> list[BufferedRecord]:
        """Remove and return everything, oldest first."""

        items = list(self._items)
        self._items.clear()
        return items

    def restore(self, records: list[BufferedRecord]) -> None:
        """Put records back after a failed flush, preserving order."""

        self._items.extendleft(reversed(records))

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[BufferedRecord]:
        return iter(self._items)
