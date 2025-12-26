import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import tempfile
import shutil
import os

# Imposta le variabili d'ambiente PRIMA di importare qualsiasi modulo che usa settings
test_keys_dir = tempfile.mkdtemp()
os.environ["KMS_PRIVATE_KEY_PATH"] = str(Path(test_keys_dir) / "private")
os.environ["KMS_PUBLIC_KEY_PATH"] = str(Path(test_keys_dir) / "public")

from app.main import app

@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    # Setup
    yield
    # Teardown
    try:
        shutil.rmtree(test_keys_dir, ignore_errors=True)
    except Exception:
        pass

@pytest.fixture(scope="function")
def client():
    with TestClient(app) as c:
        yield c
