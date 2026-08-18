"""Submission transport.

Deliberately the only module in `sdk_python.client` that imports networking.
`gaps.py` must have no path to a socket, and keeping the import surface narrow
makes that checkable by a test rather than by inspection.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable


class TransportUnavailableError(RuntimeError):
    """Ingestion could not be reached.

    Distinct from a rejection: a 4xx means our record was seen and refused, and
    buffering it would be wrong. This is only raised where the service was not
    reached at all, which is the condition IN-010 buffers for.
    """


class RecordRejectedError(RuntimeError):
    """Ingestion reached us and refused the record."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"ingestion refused the record: {status_code} {detail}")
        self.status_code = status_code
        self.detail = detail


@runtime_checkable
class Transport(Protocol):
    """Submit one complete signed record's canonical bytes."""

    def submit(self, canonical_bytes: bytes) -> None: ...


class HttpTransport:
    """POST canonical bytes to the EV-07 ingestion endpoint."""

    def __init__(self, endpoint: str, *, timeout_seconds: float = 5.0) -> None:
        if not endpoint:
            raise ValueError("an endpoint is required")
        self._endpoint = endpoint
        self._timeout = timeout_seconds

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def submit(self, canonical_bytes: bytes) -> None:
        request = urllib.request.Request(  # noqa: S310 - endpoint is operator-configured
            self._endpoint,
            data=canonical_bytes,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                if response.status >= 400:
                    raise RecordRejectedError(response.status, response.reason or "")
        except urllib.error.HTTPError as exc:
            # Reached the service and was refused. Not a buffering condition.
            raise RecordRejectedError(exc.code, exc.reason or "") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Connection refused, DNS failure, timeout: the service is absent.
            raise TransportUnavailableError(
                f"ingestion at {self._endpoint} is unreachable: {exc}"
            ) from None
