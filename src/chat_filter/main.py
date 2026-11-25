"""FromChat chat-filter service."""

from __future__ import annotations

import logging
import os
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import blocklist as blocklist_store
from .engine import explain, is_allowed

logger = logging.getLogger("uvicorn.error")

app = FastAPI(title="FromChat Chat Filter", docs_url=None, redoc_url=None)

try:
    from src.shared.middleware import add_security_middleware
except ImportError:
    add_security_middleware = None

if add_security_middleware:
    add_security_middleware(app)


class CheckRequest(BaseModel):
    text: str = ""


class CheckResponse(BaseModel):
    allowed: bool


class ExplainResponse(BaseModel):
    allowed: bool
    reason_code: str = ""
    reason_detail: str = ""


class BlocklistWordsRequest(BaseModel):
    words: List[str] = Field(default_factory=list)


@app.get("/health", response_model=None)
async def health_check():
    """Health check endpoint for Docker health checks."""
    return {"status": "healthy", "service": "chat_filter"}


@app.post("/explain", response_model=ExplainResponse)
def explain_route(body: CheckRequest) -> ExplainResponse:
    data = explain(body.text)
    return ExplainResponse(
        allowed=bool(data.get("allowed")),
        reason_code=str(data.get("reason_code") or ""),
        reason_detail=str(data.get("reason_detail") or ""),
    )


@app.post("/check", response_model=CheckResponse)
def check(body: CheckRequest) -> CheckResponse:
    allowed = is_allowed(body.text)
    logger.info(
        "check %s text=%r",
        "allowed" if allowed else "rejected",
        body.text,
    )
    return CheckResponse(allowed=allowed)


@app.get("/blocklist")
def blocklist_list() -> dict:
    return {"words": blocklist_store.get_blocklist()}


@app.post("/blocklist/add")
def blocklist_add(body: BlocklistWordsRequest) -> dict:
    added, words = blocklist_store.add_words(body.words)
    return {"added": added, "words": words}


@app.post("/blocklist/remove")
def blocklist_remove(body: BlocklistWordsRequest) -> dict:
    removed, words = blocklist_store.remove_words(body.words)
    return {"removed": removed, "words": words}


@app.post("/blocklist/clear")
def blocklist_clear() -> dict:
    blocklist_store.clear_blocklist()
    return {"words": []}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8305"))
    uvicorn.run(app, host="0.0.0.0", port=port, timeout_graceful_shutdown=5)
