from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from sparrow_comm.app import create_app
from sparrow_comm.store import Store

JWT_SECRET = "test-jwt-secret-0123456789abcdef0123"


@pytest.fixture
def store(tmp_path) -> Store:
    return Store(tmp_path / "db.sqlite", tmp_path / "data", Fernet.generate_key().decode())


@pytest.fixture
def client(store) -> TestClient:
    return TestClient(create_app(store, JWT_SECRET))


@pytest.fixture
def device(store, client):
    """An onboarded device: (api_key, unit_id, device_id)."""
    key = store.issue_onboarding_key(7, "owner@example.org")
    r = client.post(
        "/v1/onboarding",
        json={"unit_id": "unit-1"},
        headers={"X-API-Key": key, "X-Email": "owner@example.org"},
    )
    assert r.status_code == 200, r.text
    return key, "unit-1", r.json()["device_id"]
