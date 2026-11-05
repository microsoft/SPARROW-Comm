"""Send the same requests to Sparrow Studio and to sparrow-comm and compare the responses.

Each side gets its own onboarding key and Reconyx token (seeded into Studio's Postgres and into
the sparrow-comm Store); everything else in every request is byte-identical. Status codes must
match exactly. JSON bodies must match after masking values that are generated per server
(ids, tokens, timestamps). Exits 1 on any difference.
"""

import base64
import json
import os
import secrets
import sys

import httpx
import psycopg

from sparrow_comm.store import Store
from sparrow_comm.util import sha256_hex

DEVICE_PROJECT, RECONYX_PROJECT = 1001, 1002
EMAIL = "operator@sparrow.test"
VOLATILE = {"id", "token", "device_key", "api_key", "key"}
# Requests where Studio answers 500 (an unhandled exception) and sparrow-comm answers properly.
STUDIO_DEFECTS = {
    "image duplicate": "same image name on the same day hits uq_images_project_image_key",
    "audio bad confidence": "float() on a non-numeric confidence raises ValueError",
}


def seed_studio(dsn: str) -> tuple[str, str]:
    key, token = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(
            "INSERT INTO users (id, username, email, role, status)"
            " VALUES (1, 'operator', %s, 'user', 'active')"
            " ON CONFLICT (id) DO NOTHING",
            (EMAIL,),
        )
        c.execute(
            "INSERT INTO projects (id, owner_user_id, project_type, name) VALUES"
            " (%s, 1, 'sparrow', 'parity devices'), (%s, 1, 'realtime_reconyx', 'parity reconyx')"
            " ON CONFLICT (id) DO NOTHING",
            (DEVICE_PROJECT, RECONYX_PROJECT),
        )
        c.execute(
            "INSERT INTO sparrow_onboarding_keys"
            " (project_id, key_hash, key_prefix, created_by_user_id, created_by_email)"
            " VALUES (%s, %s, %s, 1, %s)",
            (DEVICE_PROJECT, sha256_hex(key), key[:8], EMAIL),
        )
        c.execute(
            "UPDATE project_reconyx_ingest_keys SET is_active=false WHERE project_id=%s", (RECONYX_PROJECT,)
        )
        c.execute(
            "INSERT INTO project_reconyx_ingest_keys (project_id, key_hash, key_prefix) VALUES (%s, %s, %s)",
            (RECONYX_PROJECT, sha256_hex(token), token[:8]),
        )
    return key, token


def seed_comm() -> tuple[str, str]:
    store = Store(
        os.environ.get("SPARROW_COMM_DB", "/var/lib/sparrow-comm/sparrow-comm.db"),
        os.environ.get("SPARROW_COMM_DATA", "/var/lib/sparrow-comm/data"),
        os.environ["SPARROW_COMM_SECRET_KEY"],
    )
    return store.issue_onboarding_key(DEVICE_PROJECT, EMAIL), store.issue_reconyx_key(RECONYX_PROJECT)


def jpeg(seed: str) -> bytes:
    return b"\xff\xd8\xff\xe0" + seed.encode() * 8 + b"\xff\xd9"


def cases(unit: str, run: str):
    """Yield (name, method, path, kwargs) with ``{key}`` and ``{token}`` placeholders."""
    img, wav = jpeg(f"img-{run}"), b"RIFF" + f"wav-{run}".encode() * 4
    meta = json.dumps({"image_name": "a.jpg", "captured_at": "2026-01-02T03:04:05Z", "detections": []})
    dev = {"X-API-Key": "{key}", "X-Unit-ID": unit}
    yield "onboarding no headers", "POST", "/v1/onboarding", {"json": {"unit_id": unit}}
    yield (
        "onboarding bad key",
        "POST",
        "/v1/onboarding",
        {
            "json": {"unit_id": unit},
            "headers": {"X-API-Key": "nope", "X-Email": EMAIL},
        },
    )
    yield (
        "onboarding wrong email",
        "POST",
        "/v1/onboarding",
        {
            "json": {"unit_id": unit},
            "headers": {"X-API-Key": "{key}", "X-Email": "other@sparrow.test"},
        },
    )
    yield (
        "onboarding no unit",
        "POST",
        "/v1/onboarding",
        {
            "json": {},
            "headers": {"X-API-Key": "{key}", "X-Email": EMAIL},
        },
    )
    yield (
        "onboarding ok",
        "POST",
        "/v1/onboarding",
        {
            "json": {"unit_id": unit},
            "headers": {"X-API-Key": "{key}", "X-Email": EMAIL},
        },
    )
    yield (
        "onboarding reuse",
        "POST",
        "/v1/onboarding",
        {
            "json": {"unit_id": unit + "-2"},
            "headers": {"X-API-Key": "{key}", "X-Email": EMAIL},
        },
    )
    yield (
        "image no auth",
        "POST",
        "/v1/uploads/image",
        {"files": {"file": ("a.jpg", img)}, "data": {"metadata": meta}},
    )
    yield (
        "image wrong unit",
        "POST",
        "/v1/uploads/image",
        {
            "files": {"file": ("a.jpg", img)},
            "data": {"metadata": meta},
            "headers": {"X-API-Key": "{key}", "X-Unit-ID": "someone-else"},
        },
    )
    yield (
        "image bad metadata",
        "POST",
        "/v1/uploads/image",
        {
            "files": {"file": ("a.jpg", img)},
            "data": {"metadata": "not json"},
            "headers": dev,
        },
    )
    yield (
        "image empty file",
        "POST",
        "/v1/uploads/image",
        {
            "files": {"file": ("a.jpg", b"")},
            "data": {"metadata": meta},
            "headers": dev,
        },
    )
    yield (
        "image ok",
        "POST",
        "/v1/uploads/image",
        {
            "files": {"file": ("a.jpg", img)},
            "data": {"metadata": meta},
            "headers": dev,
        },
    )
    yield (
        "image duplicate",
        "POST",
        "/v1/uploads/image",
        {
            "files": {"file": ("a.jpg", img)},
            "data": {"metadata": meta},
            "headers": dev,
        },
    )
    yield (
        "image person discarded",
        "POST",
        "/v1/uploads/image",
        {
            "files": {"file": ("p.jpg", jpeg(f"person-{run}"))},
            "data": {"metadata": json.dumps({"detections": [{"label": "Person"}]})},
            "headers": dev,
        },
    )
    yield (
        "legacy upload",
        "POST",
        "/v1/uploads",
        {
            "files": {"file": ("l.jpg", jpeg(f"legacy-{run}"))},
            "data": {
                "auth_key": "{key}",
                "unique_id": unit,
                "image_name": "l.jpg",
                "date": "2026-01-02 03:04:05",
            },
        },
    )
    yield (
        "legacy upload bad key",
        "POST",
        "/v1/uploads",
        {
            "files": {"file": ("l.jpg", jpeg(f"legacy2-{run}"))},
            "data": {"auth_key": "nope", "unique_id": unit},
        },
    )
    for path in ("/v1/uploads/audio", "/v1/audio_uploads"):
        yield (
            f"audio {path}",
            "POST",
            path,
            {
                "files": {"file": ("a.wav", wav + path.encode())},
                "data": {"metadata": json.dumps({"label": "owl", "confidence": 0.9})},
                "headers": dev,
            },
        )
    yield (
        "audio bad confidence",
        "POST",
        "/v1/uploads/audio",
        {
            "files": {"file": ("a.wav", wav + b"c")},
            "data": {"metadata": json.dumps({"confidence": "high"})},
            "headers": dev,
        },
    )
    for path in ("/v1/metrics/system", "/v1/system_metrics"):
        yield (
            f"metrics {path}",
            "POST",
            path,
            {"json": {"battery_voltage": 12.4, "cpu_temp_c": 41}, "headers": dev},
        )
    for path in ("/v1/metrics/starlink", "/v1/metrics"):
        yield f"metrics {path}", "POST", path, {"json": {"uptime": 5}, "headers": dev}
    yield (
        "metrics body auth",
        "POST",
        "/v1/metrics/system",
        {"json": {"auth_key": "{key}", "unique_id": unit, "battery_voltage": 12.1}},
    )
    yield "metrics not json", "POST", "/v1/metrics/system", {"content": b"x", "headers": dev}
    for path in (
        "/v1/settings/schedule",
        "/v1/get_schedule",
        "/v1/settings/audio",
        "/v1/get_scheduleaudio",
        "/v1/settings/model",
        "/v1/model_settings",
        "/v1/settings/video",
        "/v1/video_settings",
        "/v1/settings/alerts",
        "/v1/alert_settings",
        "/v1/settings/privacy",
        "/v1/privacy_settings",
    ):
        yield f"settings {path}", "POST", path, {"headers": dev}
    yield "settings no auth", "POST", "/v1/settings/schedule", {}

    rid = f"proj_{RECONYX_PROJECT}"
    rx = jpeg(f"rx-{run}")
    body = {
        "Camera_serial_number": "RXPARITY",
        "Image": base64.b64encode(rx).decode(),
        "Metadata": {"File_name": "RX_1.JPG", "date_time_taken": "2026-03-04T05:06:07+02:00"},
    }
    yield "reconyx login wrong token", "POST", "/v1/reconyx/login", {"json": {"Id": rid, "Token": "nope"}}
    yield (
        "reconyx login bad id",
        "POST",
        "/v1/reconyx/login",
        {"json": {"Id": "project-1", "Token": "{token}"}},
    )
    yield "reconyx login missing field", "POST", "/v1/reconyx/login", {"json": {"Id": rid}}
    yield "reconyx login ok", "POST", "/v1/reconyx/login", {"json": {"Id": rid, "Token": "{token}"}}
    yield "reconyx image no token", "POST", "/v1/reconyx/images", {"json": body}
    yield (
        "reconyx image bad token",
        "POST",
        "/v1/reconyx/images",
        {"json": body, "headers": {"api_key": "x.y.z"}},
    )
    yield "reconyx image ok", "POST", "/v1/reconyx/images", {"json": body, "headers": {"api_key": "{jwt}"}}
    yield (
        "reconyx image duplicate",
        "POST",
        "/v1/reconyx/images",
        {"json": body, "headers": {"api_key": "{jwt}"}},
    )
    yield (
        "reconyx image token in body",
        "POST",
        "/v1/reconyx/images",
        {"json": {**body, "Image": base64.b64encode(jpeg(f"rx2-{run}")).decode(), "Token": "{jwt}"}},
    )
    yield (
        "reconyx image bad base64",
        "POST",
        "/v1/reconyx/images",
        {
            "json": {**body, "Image": "!!!"},
            "headers": {"api_key": "{jwt}"},
        },
    )
    yield (
        "reconyx image empty",
        "POST",
        "/v1/reconyx/images",
        {
            "json": {**body, "Image": ""},
            "headers": {"api_key": "{jwt}"},
        },
    )


def fill(obj, subs: dict[str, str]):
    if isinstance(obj, str):
        for k, v in subs.items():
            obj = obj.replace("{" + k + "}", v)
        return obj
    if isinstance(obj, dict):
        return {k: fill(v, subs) for k, v in obj.items()}
    if isinstance(obj, tuple):
        return tuple(fill(v, subs) for v in obj)
    return obj


def mask(obj, key: str = ""):
    if isinstance(obj, dict):
        return {k: mask(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask(v, key) for v in obj]
    if key in VOLATILE or key.endswith(("_id", "_at")):
        return f"<{type(obj).__name__}>"
    return obj


def body_of(r: httpx.Response):
    try:
        return mask(r.json())
    except ValueError:
        return r.text


def send(c: httpx.Client, method: str, path: str, kw: dict) -> httpx.Response | None:
    # A server that crashed on the previous request drops the kept-alive socket; retry once.
    for _ in range(2):
        try:
            return c.request(method, path, **kw)
        except httpx.TransportError:
            continue
    return None


def run_side(base: str, key: str, token: str, unit: str, run: str) -> list[tuple[int, object]]:
    out = []
    subs = {"key": key, "token": token, "jwt": ""}
    with httpx.Client(base_url=base, timeout=15) as c:
        for name, method, path, kw in cases(unit, run):
            r = send(c, method, path, fill(kw, subs))
            if r is None:
                out.append((0, "<connection error>"))
                continue
            if name == "reconyx login ok" and r.status_code == 200:
                subs["jwt"] = r.json()["token"]
            out.append((r.status_code, body_of(r)))
    return out


def main() -> int:
    unit, run = f"parity-{secrets.token_hex(3)}", secrets.token_hex(4)
    s_key, s_tok = seed_studio(os.environ["STUDIO_DSN"])
    c_key, c_tok = seed_comm()
    studio = run_side(os.environ["STUDIO_URL"], s_key, s_tok, unit, run)
    comm = run_side(os.environ["COMM_URL"], c_key, c_tok, unit, run)
    names = [c[0] for c in cases(unit, run)]
    bad = known = 0
    for name, (ss, sb), (cs, cb) in zip(names, studio, comm, strict=True):
        if ss == cs and sb == cb:
            print(f"SAME  {name}  {ss}", flush=True)
            continue
        if name in STUDIO_DEFECTS and ss == 500 and cs < 500:
            known += 1
            print(f"KNOWN {name}  studio={ss} comm={cs}  (Studio defect: {STUDIO_DEFECTS[name]})")
            continue
        bad += 1
        print(f"DIFF  {name}  studio={ss} comm={cs}")
        print(f"      studio: {json.dumps(sb, default=str)[:300]}")
        print(f"      comm:   {json.dumps(cb, default=str)[:300]}")
    same = len(names) - bad - known
    print(f"\n{same}/{len(names)} identical, {known} known Studio defects, {bad} differences")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
