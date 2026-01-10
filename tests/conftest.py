import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import tempfile
import shutil
import os

# Imposta le variabili d'ambiente PRIMA di importare qualsiasi modulo che usa settings
# (Nessuna variabile per path chiavi necessaria ora che usiamo DB)

from app.main import app

@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    # Setup
    yield
    # Teardown
    try:
        # Pulizia risorse se necessario
        pass
    except Exception:
        pass

@pytest.fixture(scope="function")
def client():
    with TestClient(app) as c:
        yield c
