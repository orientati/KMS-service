from __future__ import annotations

from contextlib import asynccontextmanager

import sentry_sdk
from fastapi import FastAPI
from fastapi.responses import ORJSONResponse

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger


from app.api.v1.routes import token
from app.core.config import settings
from app.core.logging import setup_logging
from app.services.broker import AsyncBrokerSingleton
from app.services.event_handlers import handle_key_rotated
from app.services.token_service import rotate_keys

sentry_sdk.init(
    dsn=settings.SENTRY_DSN,
    send_default_pii=True,
    release=settings.SENTRY_RELEASE,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    
    # Sottoscrizione eventi RabbitMQ
    try:
        broker = AsyncBrokerSingleton()
        await broker.connect()
        await broker.subscribe("kms.events", handle_key_rotated)
    except Exception as e:
        # Logga l'errore ma non bloccare l'avvio se RabbitMQ non è raggiungibile
        from app.core.logging import get_logger
        logger = get_logger(__name__)
        logger.error(f"Impossibile sottoscriversi agli eventi RabbitMQ: {e}")

    # Setup Scheduler
    scheduler = AsyncIOScheduler()
    # Esegue rotate_keys ogni settimana (domenica) alle 2:00
    scheduler.add_job(rotate_keys, CronTrigger(day_of_week='sun', hour=2, minute=0))
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(
    title=settings.SERVICE_NAME,
    default_response_class=ORJSONResponse,
    version=settings.SERVICE_VERSION,
    lifespan=lifespan,

)

# Routers
app.include_router(token.router, prefix="/api/v1/token", tags=["token"])


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "service": settings.SERVICE_NAME}
