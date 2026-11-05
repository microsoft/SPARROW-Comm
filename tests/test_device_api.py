import json

import pytest

EMAIL = "owner@example.org"


def hdr(dev):
    key, unit, _ = dev
    return {"X-API-Key": key, "X-Unit-ID": unit}


# --- onboarding ----------------------------------------------------------------------------------


def test_onboarding_success_and_idempotent(store, client):
    key = store.issue_onboarding_key(3, EMAIL)
    h = {"X-API-Key": key, "X-Email": EMAIL.upper()}
    r = client.post("/v1/onboarding", json={"unit_id": "u1"}, headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body == {"ok": True, "project_id": 3, "device_id": body["device_id"], "unit_id": "u1"}
    again = client.post("/v1/onboarding", json={"unit_id": "u1"}, headers=h)
    assert again.status_code == 200
    assert again.json()["idempotent"] is True
    assert again.json()["device_id"] == body["device_id"]
    other = client.post("/v1/onboarding", json={"unit_id": "u2"}, headers=h)
    assert (other.status_code, other.json()["detail"]) == (409, "Key already bound to a different unit_id")


@pytest.mark.parametrize(
    ("headers", "unit", "status", "detail"),
    [
        ({"X-API-Key": "k"}, "u", 401, "Missing X-Email header"),
        ({"X-API-Key": "k", "X-Email": EMAIL}, " ", 400, "Missing unit_id"),
        ({"X-Email": EMAIL}, "u", 401, "Missing X-API-Key header"),
        ({"X-API-Key": "nope", "X-Email": EMAIL}, "u", 401, "Invalid onboarding key"),
    ],
)
def test_onboarding_errors(client, headers, unit, status, detail):
    r = client.post("/v1/onboarding", json={"unit_id": unit}, headers=headers)
    assert (r.status_code, r.json()["detail"]) == (status, detail)


def test_onboarding_wrong_email(store, client):
    key = store.issue_onboarding_key(3, EMAIL)
    r = client.post("/v1/onboarding", json={"unit_id": "u"}, headers={"X-API-Key": key, "X-Email": "x@y.z"})
    assert (r.status_code, r.json()["detail"]) == (401, "Email does not match key")


def test_onboarding_issuer_lost_access(store, client, monkeypatch):
    key = store.issue_onboarding_key(3, EMAIL)
    monkeypatch.setattr(store, "issuer_can_manage", lambda p, u: False)
    r = client.post("/v1/onboarding", json={"unit_id": "u"}, headers={"X-API-Key": key, "X-Email": EMAIL})
    assert (r.status_code, r.json()["detail"]) == (
        403,
        "Key issuer no longer has manage access to the project",
    )


# --- auth ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "detail"),
    [
        ({}, "Missing API key"),
        ({"X-API-Key": "k"}, "Missing unit_id"),
        ({"X-API-Key": "bad", "X-Unit-ID": "u"}, "Invalid API key"),
    ],
)
def test_auth_errors(client, headers, detail):
    r = client.post(
        "/v1/uploads/image", files={"file": ("a.jpg", b"x")}, data={"metadata": "{}"}, headers=headers
    )
    assert (r.status_code, r.json()["detail"]) == (401, detail)


def test_auth_unit_mismatch(client, device):
    r = client.post(
        "/v1/uploads/image",
        files={"file": ("a.jpg", b"x")},
        data={"metadata": "{}"},
        headers={"X-API-Key": device[0], "X-Unit-ID": "other"},
    )
    assert (r.status_code, r.json()["detail"]) == (401, "Unit ID does not match key")


def test_form_auth_fallback(client, device):
    key, unit, _ = device
    r = client.post(
        "/v1/uploads/image",
        files={"file": ("a.jpg", b"img")},
        data={"metadata": "{}", "auth_key": key, "unique_id": unit},
    )
    assert r.status_code == 201


# --- image upload --------------------------------------------------------------------------------


def test_image_upload_commits(store, client, device):
    meta = {
        "image_name": "my pic.jpg",
        "captured_at": "2026-01-02T03:04:05Z",
        "detections": [{"label": "deer"}],
    }
    r = client.post(
        "/v1/uploads/image",
        files={"file": ("ignored.jpg", b"jpegbytes")},
        data={"metadata": json.dumps(meta)},
        headers=hdr(device),
    )
    assert r.status_code == 201
    body = r.json()
    assert body == {
        "ok": True,
        "image_id": body["image_id"],
        "project_id": 7,
        "device_id": device[2],
        "unit_id": "unit-1",
        "discarded": False,
        "detection_count": 1,
    }
    [row] = store.items(7)
    assert row["name"] == "my_pic.jpg"
    assert row["original_name"] == "my pic.jpg"
    assert row["captured_at"] == "2026-01-02T03:04:05"
    assert row["camera_name"] == "unit-1"
    assert (store.data_dir / row["path"]).read_bytes() == b"jpegbytes"


def test_image_person_discarded(store, client, device):
    meta = {"detections": [{"label": " Person "}]}
    r = client.post(
        "/v1/uploads/image",
        files={"file": ("a.jpg", b"x")},
        data={"metadata": json.dumps(meta)},
        headers=hdr(device),
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True, "discarded": True, "reason": "privacy_person"}
    assert store.items() == []


@pytest.mark.parametrize(
    ("metadata", "content", "detail"),
    [
        ("{bad", b"x", "metadata must be valid JSON"),
        ("[1]", b"x", "metadata must be valid JSON"),
        ("{}", b"", "Empty image file"),
        ('{"detections": {"a": 1}}', b"x", "detections must be a list"),
    ],
)
def test_image_upload_400(client, device, metadata, content, detail):
    r = client.post(
        "/v1/uploads/image",
        files={"file": ("a.jpg", content)},
        data={"metadata": metadata},
        headers=hdr(device),
    )
    assert (r.status_code, r.json()["detail"]) == (400, detail)


def test_image_metadata_required(client, device):
    r = client.post("/v1/uploads/image", files={"file": ("a.jpg", b"x")}, headers=hdr(device))
    assert r.status_code == 422


def test_sink_value_error_is_400(store, client, device, monkeypatch):
    def reject(item):
        raise ValueError("project is full")

    monkeypatch.setattr(store, "commit", reject)
    r = client.post(
        "/v1/uploads/image", files={"file": ("a.jpg", b"x")}, data={"metadata": "{}"}, headers=hdr(device)
    )
    assert (r.status_code, r.json()["detail"]) == (400, "project is full")


def test_duplicate_image_returns_same_id(client, device):
    def up():
        return client.post(
            "/v1/uploads/image",
            files={"file": ("a.jpg", b"same")},
            data={"metadata": "{}"},
            headers=hdr(device),
        )

    assert up().json()["image_id"] == up().json()["image_id"]


def test_legacy_upload(store, client, device):
    key, unit, did = device
    r = client.post(
        "/v1/uploads",
        files={"file": ("a.jpg", b"legacy")},
        data={
            "auth_key": key,
            "unique_id": unit,
            "image_name": "cam.jpg",
            "detection": "deer",
            "date": "2026-01-02 03:04:05",
        },
    )
    assert r.status_code == 201
    assert r.json() == {
        "ok": True,
        "image_id": r.json()["image_id"],
        "project_id": 7,
        "device_id": did,
        "unit_id": unit,
    }
    [row] = store.items()
    assert row["captured_at"] == "2026-01-02T03:04:05"
    assert json.loads(row["detections"])[0]["label"] == "deer"
    person = client.post(
        "/v1/uploads",
        files={"file": ("a.jpg", b"p")},
        data={"auth_key": key, "unique_id": unit, "image_name": "p.jpg", "detection": "person"},
    )
    assert person.json()["discarded"] is True


def test_legacy_upload_hidden_from_schema(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert "/v1/uploads/image" in paths
    assert "/v1/uploads" not in paths
    assert "/v1/get_schedule" not in paths


# --- audio ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/v1/uploads/audio", "/v1/audio_uploads"])
def test_audio_upload(store, client, device, path):
    meta = {
        "audio_name": "bird.wav",
        "label": "owl",
        "confidence": "0.9",
        "detected_at": "2026-01-02T00:00:00Z",
    }
    r = client.post(
        path,
        files={"file": ("x.wav", b"RIFF" + path.encode())},
        data={"metadata": json.dumps(meta)},
        headers=hdr(device),
    )
    assert r.status_code == 201
    assert r.json() == {"ok": True, "audio_id": r.json()["audio_id"], "project_id": 7, "device_id": device[2]}
    row = store.items()[-1]
    assert row["kind"] == "audio"
    extra = json.loads(row["extra"])
    assert extra["label"] == "owl"
    assert extra["confidence"] == 0.9


def test_audio_errors(client, device):
    r = client.post("/v1/uploads/audio", files={"file": ("x.wav", b"")}, headers=hdr(device))
    assert (r.status_code, r.json()["detail"]) == (400, "Empty audio file")
    r = client.post(
        "/v1/uploads/audio",
        files={"file": ("x.wav", b"a")},
        data={"metadata": '{"confidence": "hi"}'},
        headers=hdr(device),
    )
    assert r.status_code == 400


# --- metrics -------------------------------------------------------------------------------------


def _metrics(store):
    with store._conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM metrics ORDER BY id")]


@pytest.mark.parametrize(
    ("path", "payload", "battery", "temp", "mtype"),
    [
        ("/v1/metrics/system", {"battery_voltage": "12.5", "cpu_temp_c": 40}, 12.5, 40.0, "system"),
        (
            "/v1/system_metrics",
            {"vedirect_battery_voltage": 12.1, "cpu_temperature": 41},
            12.1,
            41.0,
            "system",
        ),
        (
            "/v1/metrics/system",
            {"battery": {"voltage": 11}, "bme688_temperature_celsius": 20},
            11.0,
            20.0,
            "system",
        ),
        ("/v1/metrics/system", {"battery_voltage": "abc", "cpu_temp_c": 40}, None, None, "system"),
        (
            "/v1/metrics/starlink",
            {"status": {"battery_voltage": 13}, "cpu_temp_c": 50},
            13.0,
            None,
            "starlink",
        ),
        ("/v1/metrics", {"x": 1}, None, None, "starlink"),
    ],
)
def test_metrics(store, client, device, path, payload, battery, temp, mtype):
    r = client.post(path, json=payload, headers=hdr(device))
    assert r.status_code == 200
    assert r.json() == {"ok": True, "reading_id": r.json()["reading_id"], "metric_type": mtype}
    row = _metrics(store)[-1]
    assert (row["battery_voltage"], row["cpu_temp_c"], row["metric_type"]) == (battery, temp, mtype)


def test_metrics_body_auth_and_empty(client, device):
    key, unit, _ = device
    r = client.post("/v1/metrics/system", json={"auth_key": key, "unique_id": unit, "cpu_temp_c": 1})
    assert r.status_code == 200
    r = client.post("/v1/metrics/system", content=b"not json", headers=hdr(device))
    assert (r.status_code, r.json()["detail"]) == (400, "JSON body required")
    r = client.post("/v1/metrics/system", json=[1, 2], headers=hdr(device))
    assert (r.status_code, r.json()["detail"]) == (400, "JSON body required")


# --- settings ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("schedule", {"start_time": "20:15", "end_time": "20:30", "timezone": "UTC"}),
        (
            "audio",
            {
                "mode": "threshold",
                "SAMPLE_RATE": 44100,
                "MONITOR_DURATION": 1,
                "RECORD_DURATION": 2,
                "THRESHOLD": 2500,
                "SCHEDULE_INTERVAL": 60,
                "SCHEDULE_DURATION": 10,
            },
        ),
        (
            "model",
            {
                "selected_model": "AI4GAmazonClassification",
                "detection_threshold": 0.4,
                "classification_enabled": True,
                "keep_blanks": False,
            },
        ),
        ("video", {"urls": [], "selected_model": ""}),
        ("alerts", {"enabled": False, "alerts": [], "recipients": []}),
        ("privacy", {"save_person": "no"}),
    ],
)
def test_settings_defaults(client, device, path, expected):
    r = client.post(f"/v1/settings/{path}", headers=hdr(device))
    assert r.status_code == 200
    assert r.json() == expected


@pytest.mark.parametrize(
    "legacy",
    [
        "get_schedule",
        "get_scheduleaudio",
        "model_settings",
        "video_settings",
        "alert_settings",
        "privacy_settings",
    ],
)
def test_settings_legacy_body_auth(client, device, legacy):
    key, unit, _ = device
    assert client.post(f"/v1/{legacy}", json={"auth_key": key, "unique_id": unit}).status_code == 200
    assert client.post(f"/v1/{legacy}", json={}).status_code == 401


def test_settings_stored_values(store, client, device):
    store.set_device_settings(
        device[2],
        {"sleep_start_utc": "01:00", "video_url1": "rtsp://a", "video_url3": "rtsp://c", "video_model": "m"},
    )
    assert client.post("/v1/settings/schedule", headers=hdr(device)).json()["start_time"] == "01:00"
    assert client.post("/v1/settings/video", headers=hdr(device)).json() == {
        "urls": ["rtsp://a", "rtsp://c"],
        "selected_model": "m",
    }
