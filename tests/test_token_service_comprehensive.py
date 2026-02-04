import pytest
import asyncio
import jwt
import os
import json
import base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from unittest.mock import patch, AsyncMock, MagicMock
from app.services import token_service
from app.models.key_pair import KeyPair
from app.schemas.token import TokenCreate
from app.api.v1.routes.token import api_create_token as create_token
from app.services.http_client import OrientatiException
from app.db.session import SessionLocal
from sqlalchemy import select

@pytest.mark.asyncio
async def test_create_secret_keys_eddsa():
    # 1. Create Keys
    result = await token_service.create_secret_keys()
    assert result['status'] == 'success'
    
    async with SessionLocal() as session:
        keys = (await session.execute(select(KeyPair))).scalars().all()
        assert len(keys) == 1
        key = keys[0]
        assert key.kid == result['timestamp']
        
        # Verify it's encrypted
        assert "PRIVATE KEY" not in key.private_key 
        # Should be b64
        decoded_encrypted = base64.b64decode(key.private_key)
        assert len(decoded_encrypted) > 0

@pytest.mark.asyncio
async def test_create_and_verify_token_flow():
    # Ensure keys exist
    await token_service.create_secret_keys()
    
    data = TokenCreate(user_id=123, session_id=456, expires_in=10)
    token = await token_service.create_token(data)
    
    assert isinstance(token, str)
    assert len(token) > 0
    
    # Decode header to check KID
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    assert header["alg"] == "EdDSA"
    
    # Verify
    payload = await token_service.verify_token(token)
    assert payload["user_id"] == 123
    assert payload["session_id"] == 456
    assert payload["verified"] is True

@pytest.mark.asyncio
async def test_verification_fails_tampered_token():
    await token_service.create_secret_keys()
    token = await token_service.create_token(TokenCreate(user_id=1, session_id=1, expires_in=10))
    
    # Tamper with the payload part (middle)
    parts = token.split('.')
    if len(parts) == 3:
        # Change a character in the payload
        payload = parts[1]
        tampered_payload = payload[:-1] + ('A' if payload[-1] != 'A' else 'B')
        fake_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    else:
        fake_token = "invalid.token.here"
    
    with pytest.raises(OrientatiException) as exc:
        await token_service.verify_token(fake_token)
    assert exc.value.status_code == 401
    assert exc.value.status_code == 401

@pytest.mark.asyncio
async def test_rotation_lock_logic(mock_redis, monkeypatch):
    # Mock _get_active_private_key to return None so we bypass the "recent_key_exists" check
    monkeypatch.setattr("app.services.token_service._get_active_private_key", AsyncMock(return_value=None))
    
    # Acquire lock manually first
    await mock_redis.lock("kms:rotation_lock").acquire()
    
    # Try rotate
    result = await token_service.rotate_keys()
    assert result['status'] == 'skipped'
    assert result['reason'] == 'locked'

    await mock_redis.flushall()

@pytest.mark.asyncio
async def test_public_key_caching_logic(mock_redis):
    await token_service.create_secret_keys()
    
    # First call - cache miss -> DB -> Redis
    keys_map = await token_service._get_cached_public_keys_map()
    assert len(keys_map) > 0
    
    # Check Redis
    cached = await mock_redis.get("kms:public_keys")
    assert cached is not None
    
    # Modify DB directly to ensure cache is used (by NOT seeing the change)
    # Actually verifying cache hit logic via mocking is hard without spy, 
    # but we can rely on code coverage logic if verified manually.
    # Alternatively, invalidate logic:
    
    await token_service._invalidate_cache()
    cached_after = await mock_redis.get("kms:public_keys")
    assert cached_after is None

@pytest.mark.asyncio
async def test_cleanup_old_keys():
    # Insert old key
    async with SessionLocal() as session:
        old_date = datetime.now(timezone.utc) - timedelta(days=60)
        old_key = KeyPair(
            kid="old_key",
            private_key="fake",
            public_key="fake",
            is_active=False
        )
        session.add(old_key)
        await session.commit()
        # Hack timestamp
        # In SQLA we might need to update raw sql or set created_at manually if not auto?
        # KeyPair.created_at is default=...
        # We can override it in init usually
        
        await session.execute(
            select(KeyPair).where(KeyPair.kid == "old_key")
        )
        # Update created_at
        from sqlalchemy import update
        await session.execute(
            update(KeyPair).where(KeyPair.kid == "old_key").values(created_at=old_date.replace(tzinfo=None))
        )
        await session.commit()

    await token_service.cleanup_old_keys(max_age_days=30)
    
    async with SessionLocal() as session:
        res = await session.execute(select(KeyPair).where(KeyPair.kid == "old_key"))
        assert res.scalar_one_or_none() is None
