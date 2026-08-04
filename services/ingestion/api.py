"""FastAPI surface for the synchronous evidence write path."""

from __future__ import annotations

import json

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import ValidationError

from sdk_python.evidence.schema import EnvelopeValidationError

from .receipts import NonCanonicalWireError
from .service import (
    ChainConflictError,
    CollectorAuthenticationError,
    ContentSubstitutionError,
    ForkIntegrityError,
    IngestionAcknowledgement,
    IngestionError,
    IngestionService,
    LedgerUnavailableError,
    ReplayError,
)


def create_app(service: IngestionService) -> FastAPI:
    """Create an app with no queue or deferred acknowledgment path."""

    app = FastAPI(title="Evidence ingestion", version="0.1.0")

    @app.post(
        "/v1/evidence",
        response_model=IngestionAcknowledgement,
        status_code=status.HTTP_201_CREATED,
    )
    async def ingest(request: Request) -> IngestionAcknowledgement:
        raw_record = await request.body()
        try:
            return service.ingest(raw_record)
        except NonCanonicalWireError as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": "wire.non_canonical", "message": str(exc)},
            ) from exc
        except (
            EnvelopeValidationError,
            ValidationError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except CollectorAuthenticationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except (ForkIntegrityError, ContentSubstitutionError) as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": exc.error_code,
                    "message": str(exc),
                    "event_id": str(exc.event_id),
                },
            ) from exc
        except ReplayError as exc:
            raise HTTPException(
                status_code=409,
                detail={"code": exc.error_code, "message": str(exc)},
            ) from exc
        except ChainConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except IngestionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LedgerUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    return app
