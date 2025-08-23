from __future__ import annotations

import httpx
from app.core.config import settings


async def fetch_user_from_service(user_id: int) -> dict | None:
    """
    Esempio di chiamata HTTP ad un altro servizio.
    In un contesto reale inserire eventuali header dal gateway (es. X-Request-ID).
    """
    if not settings.USERS_SERVICE_URL:
        return None
    url = f"{settings.USERS_SERVICE_URL}/api/v1/users/{user_id}"
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(url)
        if resp.status_code == 200:
            return resp.json()
        return None
