from __future__ import annotations

import asyncio
import functools
import json
import logging
import base64
import redis
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, delete, desc, update

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.key_pair import KeyPair
from app.services.http_client import OrientatiException
from app.services.broker import AsyncBrokerSingleton
from app.schemas.token import TokenCreate, TokenResponse
from app.services.redis_client import get_redis_client
from app.services.secret_manager import get_secret_manager

logger = logging.getLogger(__name__)

# Cache for keys (in-memory)
_CACHED_PRIVATE_KEY_DATA: Optional[Dict] = None  # {kid, private_bytes_decrypted}
_CACHED_PUBLIC_KEYS: Optional[Dict[str, str]] = None # Dict {kid: pem_str}
_LAST_CACHE_UPDATE: Optional[datetime] = None
_CACHE_TTL = timedelta(minutes=5)


async def _get_active_private_key(retry_count: int = 0) -> Dict:
    """
    Returns dict with 'kid' and 'private_key_obj' (Ed25519PrivateKey)
    """
    global _CACHED_PRIVATE_KEY_DATA
    
    if _CACHED_PRIVATE_KEY_DATA is None:
        async with SessionLocal() as session:
            # Get the most recent active key
            result = await session.execute(
                select(KeyPair)
                .where(KeyPair.is_active == True)
                .order_by(desc(KeyPair.created_at))
                .limit(1)
            )
            key_pair = result.scalar_one_or_none()
            
            if not key_pair:
                logger.warning("No active private key found in DB. Triggering rotation...")
                rotation_result = await rotate_keys()
                if rotation_result.get('status') == 'success':
                     async with SessionLocal() as session2:
                        result2 = await session2.execute(
                            select(KeyPair)
                            .where(KeyPair.is_active == True)
                            .order_by(desc(KeyPair.created_at))
                            .limit(1)
                        )
                        key_pair = result2.scalar_one_or_none()

            if not key_pair:
                 raise OrientatiException(message="Failed to retrieve key pair", status_code=500)

            # Decrypt private key
            try:
                # Provide backward compatibility if we have old RSA keys not encrypted?
                # The task assumes full migration. We assume stored key is b64(encrypted(bytes)).
                # But to be safe, if migration happens on existing DB, old keys might be PEM.
                # However, instructions say "Elimina lo storage... in chiaro". 
                # We assume new keys are created this way. Old keys handling might fail if not careful.
                # For this task, we implement the NEW logic.
                
                encrypted_bytes = base64.b64decode(key_pair.private_key)
                manager = get_secret_manager()
                decrypted_bytes = manager.decrypt(encrypted_bytes)
                
                # Load Ed25519
                # Note: If old keys were RSA PEM strings, this will fail.
                # We assume clean slate or migration handled elsewhere.
                try:
                    private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(decrypted_bytes)
                except ValueError:
                    # Fallback check if it was RSA PEM (Legacy support scenario)
                    # Not requested but good for safety? 
                    # "Migra ... a EdDSA". Suggests we switch.
                    # If strictly EdDSA, we just proceed.
                    raise ValueError("Invalid Key Format - Expected EdDSA Private Bytes")

                _CACHED_PRIVATE_KEY_DATA = {
                    "kid": key_pair.kid,
                    "private_key_obj": private_key_obj
                }
            except Exception as e:
                logger.error(f"Failed to load/decrypt private key (kid={key_pair.kid}): {e}. Marking as inactive and retrying.")
                async with SessionLocal() as session_fix:
                    await session_fix.execute(
                        update(KeyPair)
                        .where(KeyPair.id == key_pair.id)
                        .values(is_active=False)
                    )
                    await session_fix.commit()
                
                if retry_count >= 3:
                    logger.critical("Max retry limit reached in key decryption resiliency logic.")
                    raise OrientatiException(message="Key loading error: Max retries exceeded", status_code=500)

                # Retry (will trigger rotation if no active key found)
                return await _get_active_private_key(retry_count=retry_count + 1)

    return _CACHED_PRIVATE_KEY_DATA


async def _invalidate_cache():
    global _CACHED_PRIVATE_KEY_DATA, _CACHED_PUBLIC_KEYS, _LAST_CACHE_UPDATE
    _CACHED_PRIVATE_KEY_DATA = None
    _CACHED_PUBLIC_KEYS = None
    _LAST_CACHE_UPDATE = None
    
    try:
        redis = await get_redis_client()
        await redis.delete("kms:public_keys")
    except Exception as e:
        logger.warning(f"Failed to invalidate Redis cache: {e}")


async def create_token(data: TokenCreate) -> str:
    try:
        key_data = await _get_active_private_key()
        private_key_obj = key_data["private_key_obj"]
        kid = key_data["kid"]

        payload = data.model_dump()
        if "exp" not in payload:
            if data.expires_in <= 0:
                raise OrientatiException(message="expires_in must be greater than 0", status_code=400)
            payload["exp"] = int((datetime.now(timezone.utc) + timedelta(minutes=data.expires_in)).timestamp())

        # Thread pool for cpu bound
        loop = asyncio.get_running_loop()
        token = await loop.run_in_executor(
            None, 
            functools.partial(
                jwt.encode,
                payload,
                private_key_obj,
                algorithm="EdDSA",
                headers={"kid": kid}
            )
        )
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return token
    except Exception as e:
        await _invalidate_cache()
        raise e


async def _get_cached_public_keys_map(force_refresh: bool = False) -> Dict[str, str]:
    """Returns Dict {kid: pem_str}"""
    global _CACHED_PUBLIC_KEYS, _LAST_CACHE_UPDATE
    
    now = datetime.now(timezone.utc)
    
    if (
        _CACHED_PUBLIC_KEYS is None 
        or force_refresh 
        or (_LAST_CACHE_UPDATE and now - _LAST_CACHE_UPDATE > _CACHE_TTL)
    ):
        redis = await get_redis_client()
        redis_key = "kms:public_keys"
        
        try:
            cached_json = await redis.get(redis_key)
            if cached_json and not force_refresh:
                _CACHED_PUBLIC_KEYS = json.loads(cached_json)
                _LAST_CACHE_UPDATE = now
                return _CACHED_PUBLIC_KEYS
        except Exception as e:
            logger.warning(f"Redis get failed: {e}")

        async with SessionLocal() as session:
            result = await session.execute(
                select(KeyPair)
                .where(KeyPair.is_active == True)
                .order_by(desc(KeyPair.created_at))
            )
            key_pairs = result.scalars().all()
            
            # Build map
            _CACHED_PUBLIC_KEYS = {kp.kid: kp.public_key for kp in key_pairs}
            _LAST_CACHE_UPDATE = now
            
            try:
                await redis.set(redis_key, json.dumps(_CACHED_PUBLIC_KEYS), ex=3600)
            except Exception as e:
                logger.warning(f"Redis set failed: {e}")
            
    return _CACHED_PUBLIC_KEYS


async def verify_token(token: str) -> dict:
    from jwt import InvalidTokenError
    
    try:
        # 1. Unverified Header Decode to get KID
        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
        except Exception:
             raise OrientatiException(status_code=401, message="Invalid Token Header", url="token/verify_token")

        if not kid:
            # Reject immediately if kid is missing (as per requirements)
            raise OrientatiException(status_code=401, message="Missing KID in token", url="token/verify_token")

        # 2. Get Keys Map
        keys_map = await _get_cached_public_keys_map()
        
        if kid not in keys_map:
            # Try refresh once if key not found (maybe rotated recently)
            keys_map = await _get_cached_public_keys_map(force_refresh=True)
            if kid not in keys_map:
                raise OrientatiException(status_code=401, message="Invalid Key ID (kid)", url="token/verify_token")

        pem = keys_map[kid]
        
        # 3. Verify
        loop = asyncio.get_running_loop()
        
        # Load Public Key
        # If the key is Ed25519, standard load_pem_public_key works
        public_key = serialization.load_pem_public_key(pem.encode('utf-8'))

        payload = await loop.run_in_executor(
            None,
            functools.partial(
                jwt.decode,
                token,
                public_key,
                algorithms=["EdDSA", "RS256"], # Support both if migrating, or just EdDSA
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

    except OrientatiException as e:
        raise e
    except InvalidTokenError:
         raise OrientatiException(status_code=401, message="Token invalid or expired", url="token/verify_token")
    except Exception as e:
        logger.error(f"Verification error: {e}")
        raise OrientatiException(status_code=401, message="Verification failed", url="token/verify_token")


async def create_secret_keys() -> dict:
    """
    Generates new Ed25519 keys, encrypts private key, stores in DB.
    """
    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        logger.info(f"Generating new Ed25519 key pair - id: {timestamp}")

        # Generate Ed25519
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Get Raw Bytes for private key (32 bytes)
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Encrypt Private Bytes
        manager = get_secret_manager()
        encrypted_bytes = manager.encrypt(private_bytes)
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

        # Public PEM
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Store in DB
        async with SessionLocal() as session:
            new_key = KeyPair(
                kid=timestamp,
                private_key=encrypted_b64, # Storing encrypted b64 string
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

        await _invalidate_cache()

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
            await session.execute(
                delete(KeyPair).where(KeyPair.created_at < cutoff_date)
            )
            await session.commit()
            
        logger.info("Cleaned up old keys from DB.")
        await _invalidate_cache()
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")


async def rotate_keys() -> dict:
    """
    Coordinated rotation: checks if a recent key exists before creating a new one.
    Uses Distributed Lock (Redlock pattern via redis-py) to ensure single execution.
    """
    redis_client = await get_redis_client()
    lock_name = "kms:rotation_lock"
    
    # Try to acquire lock
    try:
        # blocking_timeout=0.1 means fail almost immediately if locked
        async with redis_client.lock(lock_name, timeout=60, blocking_timeout=0.1): 
            logger.info("Acquired rotation lock.")
            
            # 1. Lazy Check
            async with SessionLocal() as session:
                 recent_cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
                 result = await session.execute(
                    select(KeyPair)
                    .where(KeyPair.created_at > recent_cutoff)
                    .where(KeyPair.is_active == True)
                    .limit(1)
                 )
                 recent_key = result.scalar_one_or_none()
                 
                 if recent_key:
                     logger.info("A recent key already exists. Skipping rotation.")
                     return {'status': 'skipped', 'reason': 'recent_key_exists'}
    
            # 2. Create New Keys
            return await create_secret_keys()
            
    except redis.exceptions.LockError:
        logger.info("Could not acquire lock for key rotation. Skipping.")
        return {'status': 'skipped', 'reason': 'locked'}
        
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
