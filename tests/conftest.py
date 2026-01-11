import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Import app modules
# Note: config settings might be loaded here, so we patch before usage
from app.main import app as fastapi_app
from app.db.base import Base
# We need to access where SessionLocal is defined
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
    Create an in-memory SQLite database, create tables, and patch SessionLocal.
    """
    # Create in-memory async engine
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        future=True,
        echo=False
    )
    
    # Create tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    # Create a test session maker
    TestSessionLocal = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False
    )
    
    # Patch the global SessionLocal in app.db.session
    with patch("app.db.session.SessionLocal", TestSessionLocal):
        yield
        
    # Teardown
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()

@pytest.fixture(scope="function")
async def client():
    async with AsyncClient(transport=ASGITransport(app=fastapi_app), base_url="http://test") as c:
        yield c

