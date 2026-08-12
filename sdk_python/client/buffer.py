"""Bounded local buffer (IN-010).

The buffer stores the signed canonical bytes verbatim. It does not store a
record object that gets re-serialized on flush, because re-serializing invites
a later change to canonicalisation or field ordering to alter bytes a signature
already covers. What was signed is what is sent.

The bound is enforced by refusing to accept, never by evicting. IN-011 requires
a gap marker *before* records are dropped, and a buffer that silently drops its
oldest entry to make room would have already destroyed the evidence by the time
anyone could mark the gap.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass


class BufferFullError(RuntimeError):
    """The bound is reached. The caller must mark the gap before discarding."""


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
        self._dropped = 0

    @property
    def bound(self) -> int:
        return self._bound

    @property
    def dropped(self) -> int:
        """Records discarded because the bound was reached."""

        return self._dropped

    def is_full(self) -> bool:
        return len(self._items) >= self._bound

    def append(self, record: BufferedRecord) -> None:
        """Accept a record, or refuse because the bound is reached."""

        if self.is_full():
            raise BufferFullError(
                f"local buffer bound of {self._bound} reached; "
                "a CoverageGap must be emitted before any record is discarded"
            )
        self._items.append(record)

    def discard_oldest(self) -> BufferedRecord:
        """Drop one record, counting it.

        Only reachable after a gap has been marked: `EvidenceClient` calls this
        after `gaps.emit`, never before, and the counter is what the acceptance
        test reads to prove the ordering.
        """

        if not self._items:
            raise BufferFullError("nothing to discard")
        self._dropped += 1
        return self._items.popleft()

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
