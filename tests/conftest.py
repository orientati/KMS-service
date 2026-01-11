import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from app.main import app

@pytest.fixture(scope="function", autouse=True)
def mock_external_deps():
    """
    Mock external dependencies to prevent actual connections or background tasks.
    Using autouse=True ensures this runs for every test function.
    """
    with patch("app.services.broker.AsyncBrokerSingleton") as MockBroker, \
         patch("app.main.AsyncIOScheduler") as MockScheduler:
        
        # Mock Broker (methods are async)
        mock_broker = AsyncMock()
        MockBroker.return_value = mock_broker
        mock_broker.connect.return_value = True
        
        # Mock Scheduler (methods are sync)
        # AsyncIOScheduler methods like start(), shutdown(), add_job() are synchronous
        mock_scheduler = MagicMock() 
        MockScheduler.return_value = mock_scheduler
        
        yield

@pytest.fixture(scope="function")
async def client():
    """
    Async client fixture for FastAPI app.
    The lifespan events (startup/shutdown) are triggered by the AsyncClient context manager.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
