import os
import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Force a clean environment for tests
TEST_DB_PATH = "test_kms.db"
os.environ["KMS_DATABASE_URL"] = f"sqlite+aiosqlite:///./{TEST_DB_PATH}"
os.environ["SENTRY_DSN"] = ""
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
    # Patch where it is used or imported
    with patch("app.services.broker.AsyncBrokerSingleton") as MockBroker, \
         patch("app.main.AsyncIOScheduler") as MockScheduler, \
         patch("app.services.token_service.AsyncBrokerSingleton") as MockBrokerTokenService:
        
        mock_broker = AsyncMock()
        mock_broker.connect.return_value = True
        
        MockBroker.return_value = mock_broker
        MockBrokerTokenService.return_value = mock_broker
        
        mock_scheduler = MagicMock() 
        MockScheduler.return_value = mock_scheduler
        
        yield

@pytest.fixture(scope="function", autouse=True)
async def setup_test_db(monkeypatch):
    """
    Create tables in the global in-memory SQLite database.
    """
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    import app.db.session
    import app.services.token_service
    
    # Recreate engine and sessionmaker for each test to avoid loop binding issues
    test_engine = create_async_engine(os.environ["KMS_DATABASE_URL"], echo=True)
    test_session_local = async_sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    # Patch throughout the app
    monkeypatch.setattr("app.db.session.engine", test_engine)
    monkeypatch.setattr("app.db.session.SessionLocal", test_session_local)
    monkeypatch.setattr("app.services.token_service.SessionLocal", test_session_local)

    from app.db.base import Base, import_models
    
    # Load models
    import_models()
    
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass
            
    # Create tables
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    yield
        
    # Critical: dispose the engine before deleting the file
    await test_engine.dispose()
    
    # Reset Broker Singleton to avoid leakage
    from app.services.broker import AsyncBrokerSingleton
    AsyncBrokerSingleton._instance = None

@pytest.fixture(autouse=True)
async def mock_redis(monkeypatch):
    import fakeredis.aioredis
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    
    # Mock Redis Lock statefully to avoid loop binding issues in fakeredis
    import redis.exceptions
    class AsyncLockMock:
        def __init__(self):
            self.locked = False
        async def __aenter__(self):
            if self.locked:
                raise redis.exceptions.LockError("Could not acquire lock")
            self.locked = True
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            self.locked = False
        async def acquire(self, blocking=True, blocking_timeout=None, token=None):
            if self.locked:
                return False
            self.locked = True
            return True
        async def release(self):
            self.locked = False

    shared_lock = AsyncLockMock()
    monkeypatch.setattr(fake_redis, "lock", lambda name, **kwargs: shared_lock)
    
    from app.services.redis_client import RedisClient
    RedisClient._instance = None
    
    # Clear token_service memory cache
    from app.services import token_service
    token_service._CACHED_PUBLIC_KEYS = None
    token_service._LAST_CACHE_UPDATE = None
    token_service._CACHED_PRIVATE_KEY_DATA = None
    
    async def get_fake_redis():
        return fake_redis
        
    monkeypatch.setattr("app.services.redis_client.get_redis_client", get_fake_redis)
    monkeypatch.setattr("app.services.token_service.get_redis_client", get_fake_redis)
    yield fake_redis
    
    # Invalidate cache before closing, but be careful with loop
    try:
        from app.services import token_service
        await token_service._invalidate_cache()
    except Exception:
        pass
        
    try:
        await fake_redis.aclose()
    except Exception:
        pass
    
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
