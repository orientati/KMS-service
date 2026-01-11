import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch
from app.main import app

@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    yield

@pytest.fixture(scope="function")
async def client():
    # Mock RabbitMQ Broker
    with patch("app.services.broker.AsyncBrokerSingleton") as MockBroker:
        mock_broker = AsyncMock()
        MockBroker.return_value = mock_broker
        mock_broker.connect.return_value = True
        
        # Mock Scheduler
        with patch("app.main.AsyncIOScheduler") as MockScheduler:
            mock_scheduler = AsyncMock()
            MockScheduler.return_value = mock_scheduler
            
            # Use AsyncClient for async tests
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                yield c
