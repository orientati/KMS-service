from __future__ import annotations

from contextlib import asynccontextmanager

import sentry_sdk
from fastapi import FastAPI
from fastapi.responses import ORJSONResponse

from app.api.v1.routes import token
from app.core.config import settings
from app.core.logging import setup_logging

sentry_sdk.init(
    dsn=settings.SENTRY_DSN,
    send_default_pii=True,
    release=settings.SENTRY_RELEASE,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    yield


app = FastAPI(
    title=settings.SERVICE_NAME,
    default_response_class=ORJSONResponse,
    version=settings.SERVICE_VERSION,
    lifespan=lifespan,

)

# Routers
app.include_router(token.router, prefix="/api/v1/token/", tags=["token"])


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "service": settings.SERVICE_NAME}
