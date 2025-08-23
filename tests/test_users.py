def test_create_user(client):
    response = client.post(
        "/users/",
        json={"email": "test@example.com", "full_name": "Test User"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["full_name"] == "Test User"
    assert "id" in data  # controllo che l'utente abbia un ID

def test_read_users(client):
    # creo prima un utente
    client.post(
        "/users/",
        json={"email": "test2@example.com", "full_name": "Another User"}
    )
    # verifico che venga restituito
    response = client.get("/users/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["email"] == "test2@example.com"
