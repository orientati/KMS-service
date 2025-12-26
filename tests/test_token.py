from fastapi.testclient import TestClient

def _create_token(client: TestClient) -> str:
    payload = {
        "user_id": 123,
        "session_id": 456,
        "expires_in": 60
    }
    response = client.post("/api/v1/token/create", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert isinstance(data["token"], str)
    return data["token"]

def test_create_token(client: TestClient):
    # Just call the helper which performs assertions
    _create_token(client)

def test_verify_token(client: TestClient):
    # First create a token using helper
    token = _create_token(client)
    
    # Then verify it
    response = client.post("/api/v1/token/verify", json={"token": token})
    assert response.status_code == 200
    data = response.json()
    assert data["verified"] is True
    assert data["user_id"] == 123
    assert data["session_id"] == 456
    assert data["expired"] is False
    assert "expires_at" in data

def test_verify_invalid_token(client: TestClient):
    response = client.post("/api/v1/token/verify", json={"token": "invalid_token_string"})
    # Expecting 401 as per exception handling in token service
    assert response.status_code == 401
    data = response.json()
    assert data["message"] == "Invalid Token"
