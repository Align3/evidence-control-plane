"""Python SDK client: emission, local signing, buffering, and gap markers.

Composes `sdk_python.evidence` for schema, canonicalisation, and signing. This
package adds custody, transport, and fail behaviour; it does not reimplement
any of the evidence primitives.
"""

from sdk_python.client.buffer import BoundedBuffer, BufferedRecord, BufferFullError
from sdk_python.client.client import (
    CUSTOMER_RECORD_TYPES,
    EmissionResult,
    EvidenceClient,
    FailClosedError,
    FlushResult,
)
from sdk_python.client.config import (
    FAIL_CLOSED_TRADE_OFF,
    ClientConfig,
    ClientConfigurationError,
    FailBehaviour,
    FamilyPolicy,
    PolicyChange,
    UnconfiguredFamilyError,
)
from sdk_python.client.gaps import build_coverage_gap
from sdk_python.client.identity import (
    REDACTED,
    SigningIdentity,
    SigningUnavailableError,
)
from sdk_python.client.transport import (
    HttpTransport,
    RecordRejectedError,
    Transport,
    TransportUnavailableError,
)

__all__ = [
    "CUSTOMER_RECORD_TYPES",
    "FAIL_CLOSED_TRADE_OFF",
    "REDACTED",
    "BoundedBuffer",
    "BufferFullError",
    "BufferedRecord",
    "ClientConfig",
    "ClientConfigurationError",
    "EmissionResult",
    "EvidenceClient",
    "FailBehaviour",
    "FailClosedError",
    "FamilyPolicy",
    "FlushResult",
    "HttpTransport",
    "PolicyChange",
    "RecordRejectedError",
    "SigningIdentity",
    "SigningUnavailableError",
    "Transport",
    "TransportUnavailableError",
    "UnconfiguredFamilyError",
    "build_coverage_gap",
]
