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

def strip_sensitive_data(event, hint):
    """
    Remove sensitive data from Sentry events.
    """
    if 'exception' in event:
        # Filter stacktrace locals if needed, or request body
        pass
        
    # Example: filtering variables in frames (if send_default_pii=True captures locals)
    # This is a basic placeholder. Real PII stripping often requires traversing the event dict.
    return event

is_debug = settings.ENVIRONMENT == "development"

sentry_sdk.init(
    dsn=settings.SENTRY_DSN,
    send_default_pii=True if is_debug else False,
    release=settings.SENTRY_RELEASE,
    before_send=None if is_debug else strip_sensitive_data
)


async def connect_broker_forever():
    from app.core.logging import get_logger
    logger = get_logger(__name__)
    broker = AsyncBrokerSingleton()
    delay = settings.RABBITMQ_CONNECTION_RETRY_DELAY
    
    while True:
        try:
            logger.info("Tentativo di connessione a RabbitMQ...")
            if await broker.connect():
                logger.info("Connessione a RabbitMQ stabilita.")
                await broker.subscribe("kms.events", handle_key_rotated)
                break
        except Exception as e:
            logger.error(f"Errore connessione RabbitMQ: {e}")
            
        logger.warning(f"RabbitMQ non disponibile. Riprovo in {delay} secondi...")
        await asyncio.sleep(delay)
        # Exponential backoff with jitter or cap
        delay = min(delay * 2, 60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.core.logging import get_logger
    logger = get_logger(__name__)
    setup_logging()
    
    # Avvia la connessione in background (modalità degradata)
    asyncio.create_task(connect_broker_forever())

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
