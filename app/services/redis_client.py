from __future__ import annotations

import logging
from typing import Optional

import redis.asyncio as redis
from app.core.config import settings

logger = logging.getLogger(__name__)

class RedisClient:
    _instance: Optional[redis.Redis] = None

    @classmethod
    def get_instance(cls) -> redis.Redis:
        if cls._instance is None:
            logger.info(f"Connecting to Redis at {settings.REDIS_URL}")
            cls._instance = redis.from_url(
                settings.REDIS_URL,
                password=settings.REDIS_PASSWORD,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True,
                retry_on_timeout=True
            )
        return cls._instance

    @classmethod
    async def close(cls):
        if cls._instance:
            logger.info("Closing Redis connection")
            await cls._instance.close()
            cls._instance = None

async def get_redis_client() -> redis.Redis:
    return RedisClient.get_instance()
