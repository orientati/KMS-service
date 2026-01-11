import pytest
from httpx import AsyncClient

async def _create_token(client: AsyncClient) -> str:
    payload = {
        "user_id": 123,
        "session_id": 456,
        "expires_in": 60
    }
    response = await client.post("/api/v1/token/create", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert isinstance(data["token"], str)
    return data["token"]

@pytest.mark.asyncio
async def test_create_token(client: AsyncClient):
    # Just call the helper which performs assertions
    await _create_token(client)

@pytest.mark.asyncio
async def test_verify_token(client: AsyncClient):
    # First create a token using helper
    token = await _create_token(client)
    
    # Then verify it
    response = await client.post("/api/v1/token/verify", json={"token": token})
    assert response.status_code == 200
    data = response.json()
    assert data["verified"] is True
    assert data["user_id"] == 123
    assert data["session_id"] == 456
    assert data["expired"] is False
    assert "expires_at" in data

@pytest.mark.asyncio
async def test_verify_invalid_token(client: AsyncClient):
    response = await client.post("/api/v1/token/verify", json={"token": "invalid_token_string"})
    # Expecting 401 as per exception handling in token service
    assert response.status_code == 401
    data = response.json()
    assert data["message"] == "Invalid Token"
