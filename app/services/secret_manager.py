from abc import ABC, abstractmethod
import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings

class SecretManager(ABC):
    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypts bytes and returns bytes (nonce + ciphertext)"""
        pass
    
    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """Decrypts bytes (nonce + ciphertext) -> plaintext"""
        pass

class LocalSecretManager(SecretManager):
    def __init__(self):
        key = settings.KMS_MASTER_KEY
        if not key:
             raise ValueError("KMS_MASTER_KEY must be set for LocalSecretManager")
             
        # Normalize key to 32 bytes
        if len(key) < 32:
             # Hash to get 32 bytes
             self.kek = hashlib.sha256(key.encode()).digest()
        else:
             try:
                 # Try decoding if it looks like base64
                 candidate = base64.b64decode(key)
                 if len(candidate) == 32:
                     self.kek = candidate
                 else:
                     self.kek = key.encode()[:32]
             except:
                 self.kek = key.encode()[:32]

    def encrypt(self, data: bytes) -> bytes:
        aesgcm = AESGCM(self.kek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 12:
            raise ValueError("Invalid data length")
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self.kek)
        return aesgcm.decrypt(nonce, ciphertext, None)

def get_secret_manager() -> SecretManager:
    # Future: support vault, aws-kms
    if settings.SECRET_MANAGER_TYPE == "vault":
        # Placeholder for Vault implementation
        pass
    return LocalSecretManager()
