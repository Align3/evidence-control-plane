"""Minimal ASGI client for step tests.

Extracted from `test_ingestion_steps.py` so EV-08's acceptance can post to the
same ingestion app without a second copy. There is no `httpx` in this
environment, so `starlette.testclient` is unavailable; this drives the ASGI
callable directly, which is also closer to what the scenarios describe.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI


@dataclass(frozen=True, slots=True)
class ASGIResponse:
    status_code: int
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


async def asgi_post_async(app: FastAPI, path: str, body: bytes) -> ASGIResponse:
    messages: list[dict[str, Any]] = []
    request_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.5"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": [(b"content-type", b"application/json")],
            "client": ("test", 123),
            "server": ("testserver", 80),
        },
        receive,
        send,
    )
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return ASGIResponse(status_code=start["status"], body=response_body)


def asgi_post(app: FastAPI, path: str, body: bytes) -> ASGIResponse:
    """Synchronous wrapper for step definitions that are not async."""

    return asyncio.run(asgi_post_async(app, path, body))
