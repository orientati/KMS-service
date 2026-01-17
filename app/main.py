from __future__ import annotations

import asyncio
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
    from app.core.logging import get_logger
    logger = get_logger(__name__)
    setup_logging()
    
    # Sottoscrizione eventi RabbitMQ
    try:
        broker = AsyncBrokerSingleton()
        connected = False
        for i in range(settings.RABBITMQ_CONNECTION_RETRIES):
            logger.info(f"Connecting to RabbitMQ (attempt {i + 1}/{settings.RABBITMQ_CONNECTION_RETRIES})...")
            connected = await broker.connect()
            if connected:
                break
            logger.warning(
                f"Failed to connect to RabbitMQ. Retrying in {settings.RABBITMQ_CONNECTION_RETRY_DELAY} seconds...")
            await asyncio.sleep(settings.RABBITMQ_CONNECTION_RETRY_DELAY)
            
        if connected:
            await broker.subscribe("kms.events", handle_key_rotated)
        else:
            logger.error("Could not connect to RabbitMQ after multiple attempts. Exiting...")
            import sys
            sys.exit(1)
    except Exception as e:
        logger.error(f"Impossibile sottoscriversi agli eventi RabbitMQ: {e}")
        import sys
        sys.exit(1)

    # Setup Scheduler
    scheduler = AsyncIOScheduler()
    scheduler.add_job(rotate_keys, CronTrigger(day_of_week='sun', hour=2, minute=0))
    scheduler.start()
    
    yield
    try:
        # Recupera l'istanza del broker per chiuderla
        broker = AsyncBrokerSingleton()
        await broker.close()
        
        scheduler.shutdown()
        
        # Flush Sentry events
        import sentry_sdk
        sentry_sdk.flush(timeout=2.0)
    except Exception as e:
        logger.error(f"Errore durante lo shutdown: {e}")


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
