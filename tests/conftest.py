import os
import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Force a clean environment for tests
TEST_DB_PATH = "test_kms.db"
os.environ["KMS_DATABASE_URL"] = f"sqlite+aiosqlite:///./{TEST_DB_PATH}"
os.environ["KMS_ENVIRONMENT"] = "testing"
os.environ["KMS_SENTRY_DSN"] = ""

# Now import app modules
from app.main import app as fastapi_app
from app.db.base import Base
import app.db.session

@pytest.fixture(scope="function", autouse=True)
def mock_external_deps():
    """
    Mock external dependencies to prevent actual connections or background tasks.
    """
    with patch("app.services.broker.AsyncBrokerSingleton") as MockBroker, \
         patch("app.main.AsyncIOScheduler") as MockScheduler:
        
        mock_broker = AsyncMock()
        MockBroker.return_value = mock_broker
        mock_broker.connect.return_value = True
        
        mock_scheduler = MagicMock() 
        MockScheduler.return_value = mock_scheduler
        
        yield

@pytest.fixture(scope="function", autouse=True)
async def setup_test_db():
    """
    Create tables in the global in-memory SQLite database.
    """
    from app.db.session import engine
    from app.db.base import Base, import_models
    
    # Load models
    import_models()
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    yield
        
    # Critical: dispose the engine before deleting the file
    await engine.dispose()
    
    # Reset Broker Singleton and Token Service Cache to avoid leakage
    from app.services.broker import AsyncBrokerSingleton
    from app.services import token_service
    AsyncBrokerSingleton._instance = None
    token_service._invalidate_cache()
    
    # Delete the test database file
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception as e:
            pass

@pytest.fixture(scope="function")
async def client():
    async with AsyncClient(transport=ASGITransport(app=fastapi_app), base_url="http://test") as c:
        yield c
