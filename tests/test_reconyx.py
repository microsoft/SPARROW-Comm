import base64
import time

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sparrow_comm.app import create_app
from sparrow_comm.reconyx import make_reconyx_router, parse_captured_at

from .conftest import JWT_SECRET


@pytest.fixture
def token(store, client):
    raw = store.issue_reconyx_key(5)
    r = client.post("/v1/reconyx/login", json={"Id": "proj_5", "Token": raw})
    assert r.status_code == 200
    assert r.json()["message"] == "ok"
    return r.json()["token"]


def body(**kw):
    b = {"Camera_serial_number": "RX123", "Image": base64.b64encode(b"jpeg!").decode()}
    b.update(kw)
    return b


@pytest.mark.parametrize(
    "creds", [{"Id": "proj_5", "Token": "wrong"}, {"Id": "proj_x", "Token": "t"}, {"Id": "5", "Token": "t"}]
)
def test_login_invalid(store, client, creds):
    store.issue_reconyx_key(5)
    r = client.post("/v1/reconyx/login", json=creds)
    assert (r.status_code, r.json()["detail"]) == (401, "id and token combination is invalid")


def test_login_lowercase_fields_and_old_key_revoked(store, client):
    old = store.issue_reconyx_key(5)
    new = store.issue_reconyx_key(5)
    assert client.post("/v1/reconyx/login", json={"id": "proj_5", "token": old}).status_code == 401
    assert client.post("/v1/reconyx/login", json={"id": "proj_5", "token": new}).status_code == 200


def test_images_commit(store, client, token):
    meta = {"File_name": "IMG_1.JPG", "date_time_taken": "2026-03-04T05:06:07+02:00"}
    r = client.post(
        "/v1/reconyx/images", json=body(Metadata=meta, Image_group="g1"), headers={"api_key": token}
    )
    assert r.status_code == 200
    assert r.json() == {"200": 1, "image_id": r.json()["image_id"]}
    [row] = store.items(5)
    assert (row["channel"], row["camera_name"], row["original_name"]) == ("reconyx", "RX123", "IMG_1.JPG")
    assert row["captured_at"] == "2026-03-04T03:06:07"
    again = client.post("/v1/reconyx/images", json=body(Token=token))
    assert again.json()["image_id"] == r.json()["image_id"]


def test_images_errors(client, token):
    h = {"api_key": token}
    assert client.post("/v1/reconyx/images", json=body()).json()["detail"] == "Missing api_key"
    r = client.post("/v1/reconyx/images", json=body(), headers={"api_key": "garbage"})
    assert (r.status_code, r.json()["detail"]) == (401, "Invalid token")
    r = client.post("/v1/reconyx/images", content=b"{nope", headers=h)
    assert (r.status_code, r.json()["detail"]) == (400, "Body must be valid JSON")
    assert client.post("/v1/reconyx/images", json={"Image": "x"}, headers=h).status_code == 422
    r = client.post("/v1/reconyx/images", json=body(Image="!!!"), headers=h)
    assert r.json()["detail"] == "Image is not valid base64"
    r = client.post("/v1/reconyx/images", json=body(Image=""), headers=h)
    assert r.json()["detail"] == "Image is empty"
    r = client.post("/v1/reconyx/images", json=body(Camera_serial_number=" "), headers=h)
    assert r.json()["detail"] == "Camera_serial_number required"


def test_token_expired_and_revoked(store, client, token):
    now = int(time.time())
    expired = jwt.encode(
        {"project_id": 5, "key_id": 1, "iat": now - 100, "exp": now - 10}, JWT_SECRET, "HS256"
    )
    r = client.post("/v1/reconyx/images", json=body(), headers={"api_key": expired})
    assert r.json()["detail"] == "Token expired"
    bad_payload = jwt.encode({"project_id": 5}, JWT_SECRET, "HS256")
    assert client.post("/v1/reconyx/images", json=body(), headers={"api_key": bad_payload}).json()[
        "detail"
    ] == ("Invalid token payload")
    store.issue_reconyx_key(5)  # revokes the key behind `token`
    r = client.post("/v1/reconyx/images", json=body(), headers={"api_key": token})
    assert (r.status_code, r.json()["detail"]) == (401, "Unauthorized")


def test_payload_too_large(store):
    app = FastAPI()
    app.include_router(make_reconyx_router(store, store, JWT_SECRET, max_body_bytes=100))
    c = TestClient(app)
    r = c.post("/v1/reconyx/images", json=body(Image=base64.b64encode(b"x" * 500).decode()))
    assert (r.status_code, r.json()["detail"]) == (413, "Image payload too large")


def test_no_jwt_secret_is_503(store):
    c = TestClient(create_app(store, ""))
    raw = store.issue_reconyx_key(5)
    assert c.post("/v1/reconyx/login", json={"Id": "proj_5", "Token": "bad"}).status_code == 401
    r = c.post("/v1/reconyx/login", json={"Id": "proj_5", "Token": raw})
    assert (r.status_code, r.json()["detail"]) == (503, "Reconyx ingest not configured")
    assert c.post("/v1/reconyx/images", json=body(), headers={"api_key": "x"}).status_code == 503


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-01-01T10:00:00Z", "2026-01-01T10:00:00"),
        ("2026-01-01 10:00:00", "2026-01-01T10:00:00"),
        ("2026-01-01T10:00:00-0500", "2026-01-01T15:00:00"),
        ("garbage", None),
        (None, None),
    ],
)
def test_parse_captured_at(raw, expected):
    got = parse_captured_at(raw)
    assert (got.isoformat() if got else None) == expected
