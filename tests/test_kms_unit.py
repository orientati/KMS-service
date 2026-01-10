import pytest
import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from app.services import token_service
from app.models.key_pair import KeyPair

@pytest.fixture
def mock_settings():
    with patch("app.services.token_service.settings") as mock:
        mock.RABBITMQ_HOST = "localhost"
        yield mock

@pytest.fixture
def mock_session():
    # Helper to mock the async session context manager
    mock_session = AsyncMock()
    
    # Mock execute result
    mock_result = MagicMock()
    mock_session.execute.return_value = mock_result
    mock_result.scalar_one_or_none.return_value = None # Default no key
    mock_result.scalars.return_value.all.return_value = []
    
    # session.add is synchronous in AsyncSession
    mock_session.add = MagicMock()

    # Mock SessionLocal() returning a context manager that yields mock_session
    mock_session_factory = MagicMock()
    mock_session_factory.return_value.__aenter__.return_value = mock_session
    mock_session_factory.return_value.__aexit__.return_value = None
    
    return mock_session_factory, mock_session, mock_result

@pytest.mark.asyncio
async def test_get_cached_private_key_hit_db(mock_session):
    mock_factory, session, result = mock_session
    
    # Setup: DB returns a key
    fake_key = KeyPair(id=1, kid="test", private_key="FAKE_PEM", public_key="FAKE_PUB", is_active=True)
    result.scalar_one_or_none.return_value = fake_key
    
    with patch("app.services.token_service.SessionLocal", mock_factory):
        # Clear cache
        token_service._invalidate_cache()
        
        # Call
        key = await token_service._get_cached_private_key()
        
        # Verify
        assert key == "FAKE_PEM"
        assert token_service._CACHED_PRIVATE_KEY == "FAKE_PEM"
        # Verify DB call
        assert session.execute.called

@pytest.mark.asyncio
async def test_get_cached_private_key_triggers_rotation(mock_session):
    mock_factory, session, result = mock_session
    
    # Setup: DB returns None initially
    result.scalar_one_or_none.return_value = None
    
    with patch("app.services.token_service.SessionLocal", mock_factory):
        with patch("app.services.token_service.rotate_keys", new_callable=AsyncMock) as mock_rotate:
             mock_rotate.return_value = {'status': 'success'}
             
             # Need to simulate DB returning key AFTER rotation?
             # In my implementation logic:
             # if rotation_result.get('status') == 'success':
             #    async with SessionLocal() as session2: ...
             
             # So session is called twice.
             # We can use side_effect on scalar_one_or_none to return None first, then Key
             fake_key = KeyPair(id=2, kid="new", private_key="NEW_PEM", public_key="NEW_PUB", is_active=True)
             result.scalar_one_or_none.side_effect = [None, fake_key]
             
             token_service._invalidate_cache()
             key = await token_service._get_cached_private_key()
             
             assert key == "NEW_PEM"
             assert mock_rotate.called

@pytest.mark.asyncio
async def test_create_secret_keys(mock_session):
    mock_factory, session, result = mock_session
    
    with patch("app.services.token_service.SessionLocal", mock_factory):
        with patch("app.services.token_service.AsyncBrokerSingleton") as MockBroker:
             mock_broker = AsyncMock()
             MockBroker.return_value = mock_broker
             mock_broker.connect.return_value = True
             
             token_service._invalidate_cache()
             res = await token_service.create_secret_keys()
             
             assert res['status'] == 'success'
             # assert DB add called
             assert session.add.called
             assert session.commit.called
             # assert RabbitMQ publish
             assert mock_broker.publish_message.called
             assert mock_broker.publish_message.call_args[1]['msg_type'] == "KMS.KEY_ROTATED"
