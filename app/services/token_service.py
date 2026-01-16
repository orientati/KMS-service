from __future__ import annotations

import asyncio
import functools
import jwt
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select, delete, desc

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.key_pair import KeyPair
from app.services.http_client import OrientatiException
from app.services.broker import AsyncBrokerSingleton
from app.schemas.token import TokenCreate, TokenResponse

logger = logging.getLogger(__name__)

# Cache for keys (in-memory)
_CACHED_PRIVATE_KEY: Optional[str] = None  # PEM string
_CACHED_PUBLIC_KEYS: Optional[List[str]] = None # List of PEM strings
_LAST_CACHE_UPDATE: Optional[datetime] = None
_CACHE_TTL = timedelta(minutes=5)


async def _get_cached_private_key() -> str:
    global _CACHED_PRIVATE_KEY
    if _CACHED_PRIVATE_KEY is None:
        # Fetch from DB
        async with SessionLocal() as session:
            # Get the most recent active key
            result = await session.execute(
                select(KeyPair)
                .where(KeyPair.is_active == True)
                .order_by(desc(KeyPair.created_at))
                .limit(1)
            )
            key_pair = result.scalar_one_or_none()
            
            if key_pair:
                _CACHED_PRIVATE_KEY = key_pair.private_key
            else:
                # No key found? Try to rotate (lazy init)
                logger.warning("No active private key found in DB. Triggering rotation...")
                rotation_result = await rotate_keys()
                
                if rotation_result.get('status') == 'success':
                     # After successful rotation, the cache should be invalidated,
                     # so we can re-fetch the newly created key.
                     # For simplicity and to avoid recursive calls, we'll re-query the DB.
                     # _invalidate_cache() is called by rotate_keys, so _CACHED_PRIVATE_KEY is None.
                     # We can either call this function recursively (carefully) or re-query.
                     # Re-querying here is safer.
                     async with SessionLocal() as session2:
                        result2 = await session2.execute(
                            select(KeyPair)
                            .where(KeyPair.is_active == True)
                            .order_by(desc(KeyPair.created_at))
                            .limit(1)
                        )
                        kp2 = result2.scalar_one_or_none()
                        if kp2:
                             _CACHED_PRIVATE_KEY = kp2.private_key
                        else:
                             raise OrientatiException(message="Failed to retrieve key after rotation", status_code=500)
                else:
                    raise OrientatiException(message="Failed to rotate keys", status_code=500)

    return _CACHED_PRIVATE_KEY


def _invalidate_cache():
    global _CACHED_PRIVATE_KEY, _CACHED_PUBLIC_KEYS, _LAST_CACHE_UPDATE
    _CACHED_PRIVATE_KEY = None
    _CACHED_PUBLIC_KEYS = None
    _LAST_CACHE_UPDATE = None


async def create_token(data: TokenCreate) -> str:
    try:
        private_key = await _get_cached_private_key()
        
        # Load object
        private_key_obj = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=None
        )

        payload = data.model_dump()
        if "exp" not in payload:
            payload["exp"] = int((datetime.now(timezone.utc) + timedelta(minutes=data.expires_in)).timestamp())

        # Thread pool for cpu bound
        loop = asyncio.get_running_loop()
        token = await loop.run_in_executor(
            None, 
            functools.partial(
                jwt.encode,
                payload,
                private_key_obj,
                algorithm="RS256"
            )
        )
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token
    except Exception as e:
        _invalidate_cache()
        raise e


async def _get_cached_public_keys(force_refresh: bool = False) -> List[str]:
    global _CACHED_PUBLIC_KEYS, _LAST_CACHE_UPDATE
    
    now = datetime.now(timezone.utc)
    
    if (
        _CACHED_PUBLIC_KEYS is None 
        or force_refresh 
        or (_LAST_CACHE_UPDATE and now - _LAST_CACHE_UPDATE > _CACHE_TTL)
    ):
        async with SessionLocal() as session:
            result = await session.execute(
                select(KeyPair.public_key)
                .where(KeyPair.is_active == True)
                .order_by(desc(KeyPair.created_at))
            )
            keys = result.scalars().all()
            _CACHED_PUBLIC_KEYS = list(keys)
            _LAST_CACHE_UPDATE = now
            
    return _CACHED_PUBLIC_KEYS


async def verify_token(token: str) -> dict:
    from jwt import InvalidTokenError
    
    try:
        public_keys_pems = await _get_cached_public_keys()
        
        last_exception = None
        loop = asyncio.get_running_loop()

        for pem in public_keys_pems:
            try:
                public_key = serialization.load_pem_public_key(pem.encode('utf-8'))
                
                # Esegui jwt.decode (CPU-bound) in un thread pool
                payload = await loop.run_in_executor(
                    None,
                    functools.partial(
                        jwt.decode,
                        token,
                        public_key,
                        algorithms=["RS256"],
                        options={"verify_aud": False}
                    )
                )
                
                now = datetime.now(timezone.utc).timestamp()
                exp = payload.get("exp", now + 1)
                
                expired = now > exp
                return {
                    **payload,
                    "verified": True,
                    "expired": expired,
                    "expires_at": int(exp)
                }
            except InvalidTokenError as e:
                last_exception = e
                continue
            except Exception as e:
                logger.error(f"Errore decodifica token con una chiave: {e}")
                continue

        raise last_exception if last_exception else InvalidTokenError("Nessuna chiave disponibile per la verifica")

    except OrientatiException as e:
        raise e
    except InvalidTokenError:
         raise OrientatiException(status_code=401, message="Token non valido", details={"message": "Firma del token non valida o scaduta"}, url="token/verify_token")
    except Exception as e:
        raise OrientatiException(exc=e, url="token/verify_token", status_code=401, message="Token non valido", details={"message": "Impossibile verificare il token"})


async def create_secret_keys() -> dict:
    """
    Genera nuove chiavi RSA e le salva nel DB.
    """
    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        logger.info(f"Generating new key pair - id: {timestamp}")

        # Generate RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Store in DB
        async with SessionLocal() as session:
            # Optional: Mark old keys as inactive?
            # For now just insert new one.
            new_key = KeyPair(
                kid=timestamp,
                private_key=pem_private,
                public_key=pem_public,
                is_active=True
            )
            session.add(new_key)
            await session.commit()
            await session.refresh(new_key)

        logger.info("New key pair saved to DB.")
        
        # Publish Event
        broker = AsyncBrokerSingleton()
        if await broker.connect():
             await broker.publish_message(
                 exchange_name="kms.events", 
                 msg_type="KMS.KEY_ROTATED", 
                 data={"kid": timestamp}
             )

        _invalidate_cache()

        # Invalidate cache after rotation
        _invalidate_cache()

        return {
            'timestamp': timestamp,
            'status': 'success'
        }

    except Exception as e:
        raise OrientatiException(exc=e, url="token/create_secret_keys")


async def cleanup_old_keys(max_age_days: int = 30):
    try:
        if max_age_days <= 0: return

        cutoff_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max_age_days)
        
        async with SessionLocal() as session:
            # Delete keys older than cutoff
            # Note: We might want to keep public keys longer? 
            # For now, delete rows created < cutoff
            
            # Using execute delete
            await session.execute(
                delete(KeyPair).where(KeyPair.created_at < cutoff_date)
            )
            await session.commit()
            
        logger.info("Cleaned up old keys from DB.")
        _invalidate_cache()
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")


async def rotate_keys() -> dict:
    """
    Coordinated rotation: checks if a recent key exists before creating a new one.
    """
    try:
        # 1. Lazy Check
        async with SessionLocal() as session:
             # Check for any key created in last 24h
             recent_cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
             result = await session.execute(
                select(KeyPair)
                .where(KeyPair.created_at > recent_cutoff)
                .limit(1)
             )
             recent_key = result.scalar_one_or_none()
             
             if recent_key:
                 logger.info("A recent key already exists (created < 24h ago). Skipping rotation.")
                 return {'status': 'skipped', 'reason': 'recent_key_exists'}

        # 2. Create New Keys
        return await create_secret_keys()
        
        # 3. Cleanup Old
        # We can run cleanup async separately
        # await cleanup_old_keys()

    except Exception as e:
        logger.error(f"Rotation failed: {e}")
        return {'status': 'error', 'error': str(e)}


async def list_available_public_keys() -> List[dict]:
    # Used for API response potentially
    async with SessionLocal() as session:
        result = await session.execute(
            select(KeyPair).order_by(desc(KeyPair.created_at))
        )
        keys = result.scalars().all()
        
    return [
        {
            'kid': k.kid,
            'created_at': k.created_at,
            'is_active': k.is_active
        }
        for k in keys
    ]
