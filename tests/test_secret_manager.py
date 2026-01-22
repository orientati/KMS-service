import pytest
from app.services.secret_manager import LocalSecretManager, get_secret_manager
from app.core.config import settings

def test_local_secret_manager_encryption_flow():
    # Setup fixed key
    settings.KMS_MASTER_KEY = "test_key_must_be_long_enough_or_will_be_hashed"
    manager = LocalSecretManager()
    
    data = b"my_secret_data"
    encrypted = manager.encrypt(data)
    
    # Ciphertext should be different from plaintext and longer (nonce + tag)
    assert encrypted != data
    assert len(encrypted) > len(data)
    
    decrypted = manager.decrypt(encrypted)
    assert decrypted == data

def test_local_secret_manager_consistency():
    settings.KMS_MASTER_KEY = "consistent_key"
    manager1 = LocalSecretManager()
    manager2 = LocalSecretManager()
    
    data = b"data"
    encrypted = manager1.encrypt(data)
    decrypted = manager2.decrypt(encrypted)
    
    assert decrypted == data

def test_decrypt_invalid_data():
    manager = LocalSecretManager()
    with pytest.raises(Exception):
        manager.decrypt(b"invalid_data_too_short")
