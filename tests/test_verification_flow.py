import pytest
from app.services import token_service
from app.schemas.token import TokenCreate
from app.services.secret_manager import get_secret_manager

@pytest.mark.asyncio
async def test_token_creation_and_verification_end_to_end():
    """
    Test di verifica del flusso completo:
    1. Inizializzazione chiavi (se necessario)
    2. Creazione Token
    3. Verifica Token
    """
    # 1. Ensure keys exist (simulate rotation)
    _ = get_secret_manager() 
    await token_service.rotate_keys()
    
    # 2. Create Token
    token_data = TokenCreate(user_id=100, session_id=200, expires_in=10)
    token = await token_service.create_token(token_data)
    
    assert token is not None
    assert len(token) > 0
    
    # 3. Verify Token
    payload = await token_service.verify_token(token)
    
    assert payload['verified'] is True
    assert payload['user_id'] == 100
    assert payload['session_id'] == 200
