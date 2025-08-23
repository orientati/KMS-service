from __future__ import annotations

import asyncio
import aio_pika
from aio_pika import ExchangeType
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.db.session import SessionLocal
from app.services.user_service import upsert_user_from_event

logger = get_logger(__name__)


async def _consume_users_queue() -> None:
    """
    Consumatore semplice:
      - dichiara exchange 'user.events' (topic)
      - dichiara queue 'user_service_user_events'
      - binding key 'user.*'
    """
    connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=32)

        exchange = await channel.declare_exchange("user.events", ExchangeType.TOPIC, durable=True)
        queue = await channel.declare_queue("users_service_user_events", durable=True)
        await queue.bind(exchange, routing_key="user.*")

        async with queue.iterator() as queue_iter:
            async for message in queue_iter:
                async with message.process(requeue=False):
                    body = message.body.decode()
                    logger.info("Received user event")
                    # Usa una sessione breve per ogni messaggio
                    db = SessionLocal()
                    try:
                        upsert_user_from_event(db, body)
                    finally:
                        db.close()


async def main() -> None:
    setup_logging()
    logger.info("Starting broker consumer...")
    await _consume_users_queue()


if __name__ == "__main__":
    asyncio.run(main())
