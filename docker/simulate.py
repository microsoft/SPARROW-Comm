"""Drive every receive channel of a running sparrow-comm stack, then check what arrived.

Acts as the operator (issues keys through the shared Store), a field device, a Reconyx
cloud forwarder, an FTPS camera and an e-mail camera. Exits non-zero if any item is missing.
"""

import base64
import ftplib
import io
import json
import os
import secrets
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage

import httpx

from sparrow_comm.store import Store

API = os.environ.get("API_URL", "http://localhost:8000")
PROJECT = int(os.environ.get("SIM_PROJECT", "1001"))
EMAIL = "operator@sparrow.test"
CAM_MAIL, CAM_MAIL_PW = "cam@sparrow.test", "campw"
TIMEOUT = float(os.environ.get("SIM_TIMEOUT", "60"))

results: list[tuple[str, bool, str]] = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)


def jpeg() -> bytes:
    return b"\xff\xd8\xff\xe0" + secrets.token_bytes(64) + b"\xff\xd9"


def main() -> int:
    store = Store(
        os.environ["SPARROW_COMM_DB"], os.environ["SPARROW_COMM_DATA"], os.environ["SPARROW_COMM_SECRET_KEY"]
    )
    before = {r["sha256"] for r in store.items(PROJECT)}
    expect: dict[str, str] = {}

    # Field device: onboarding, image, privacy discard, legacy upload, audio, metrics, settings.
    unit = f"sim-{secrets.token_hex(3)}"
    key = store.issue_onboarding_key(PROJECT, EMAIL)
    c = httpx.Client(base_url=API, timeout=10)
    r = c.post("/v1/onboarding", json={"unit_id": unit}, headers={"X-API-Key": key, "X-Email": EMAIL})
    check("device onboarding", r.status_code == 200, r.text)
    h = {"X-API-Key": key, "X-Unit-ID": unit}
    img = jpeg()
    meta = {"image_name": "sim.jpg", "captured_at": "2026-01-02T03:04:05Z", "detections": [{"label": "deer"}]}
    r = c.post(
        "/v1/uploads/image", files={"file": ("sim.jpg", img)}, data={"metadata": json.dumps(meta)}, headers=h
    )
    check("device image", r.status_code == 201, r.text)
    expect["device image"] = img
    meta = {"detections": [{"label": "person"}]}
    r = c.post(
        "/v1/uploads/image", files={"file": ("p.jpg", jpeg())}, data={"metadata": json.dumps(meta)}, headers=h
    )
    check("device privacy discard", r.status_code == 200 and r.json().get("discarded") is True, r.text)
    legacy = jpeg()
    r = c.post(
        "/v1/uploads",
        files={"file": ("legacy.jpg", legacy)},
        data={"auth_key": key, "unique_id": unit, "image_name": "legacy.jpg", "date": "2026-01-02 03:04:05"},
    )
    check("device legacy upload", r.status_code == 201, r.text)
    expect["device legacy upload"] = legacy
    wav = b"RIFF" + secrets.token_bytes(32)
    r = c.post(
        "/v1/uploads/audio", files={"file": ("a.wav", wav)}, data={"metadata": '{"label": "owl"}'}, headers=h
    )
    check("device audio", r.status_code == 201, r.text)
    expect["device audio"] = wav
    r = c.post("/v1/metrics/system", json={"battery_voltage": 12.4, "cpu_temp_c": 41}, headers=h)
    check("device metrics", r.status_code in (200, 201), r.text)
    r = c.post("/v1/settings/schedule", headers=h)
    check("device settings", r.status_code == 200 and "start_time" in r.json(), r.text)
    r = c.post("/v1/uploads/image", files={"file": ("x.jpg", b"x")}, data={"metadata": "{}"}, headers={})
    check("device auth rejected", r.status_code == 401, r.text)

    # Reconyx cloud forwarder.
    token = store.issue_reconyx_key(PROJECT)
    r = c.post("/v1/reconyx/login", json={"Id": f"proj_{PROJECT}", "Token": token})
    check("reconyx login", r.status_code == 200, r.text[:80])
    rx = jpeg()
    body = {
        "Camera_serial_number": "RXSIM",
        "Image": base64.b64encode(rx).decode(),
        "Metadata": {"File_name": "RX_1.JPG", "date_time_taken": "2026-03-04T05:06:07+02:00"},
    }
    r = c.post("/v1/reconyx/images", json=body, headers={"api_key": r.json().get("token", "")})
    check("reconyx image", r.status_code == 200, r.text)
    expect["reconyx image"] = rx

    # FTPS camera.
    pw = store.set_ftps_password(PROJECT)
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ft = jpeg()
    try:
        f = ftplib.FTP_TLS(context=ctx)
        f.connect(
            os.environ.get("FTPS_HOST", "localhost"), int(os.environ.get("FTPS_PORT", "2121")), timeout=10
        )
        f.login(f"proj_{PROJECT}", pw)
        f.prot_p()
        f.storbinary("STOR SimCam_00_20260102030405.jpg", io.BytesIO(ft))
        f.quit()
        check("ftps upload", True)
    except Exception as e:  # noqa: BLE001
        check("ftps upload", False, repr(e))
    expect["ftps item"] = ft

    # E-mail camera: the mailbox sends to itself, as Studio requires.
    store.set_imap_account(PROJECT, CAM_MAIL, CAM_MAIL_PW)
    em = jpeg()
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = f"Trail Cam <{CAM_MAIL}>", CAM_MAIL, "Photo from SimMailCam"
    m.set_content("sim")
    m.add_attachment(em, maintype="image", subtype="jpeg", filename="mail.jpg")
    try:
        with smtplib.SMTP(
            os.environ.get("SMTP_HOST", "localhost"), int(os.environ.get("SMTP_PORT", "3025"))
        ) as s:
            s.send_message(m)
        check("smtp send", True)
    except Exception as e:  # noqa: BLE001
        check("smtp send", False, repr(e))
    expect["imap item"] = em

    # Wait for the pull channels, then confirm every expected payload was committed once.
    from sparrow_comm.util import sha256_bytes

    want = {name: sha256_bytes(data) for name, data in expect.items()}
    deadline = time.time() + TIMEOUT
    while True:
        rows = {r["sha256"]: r for r in store.items(PROJECT)}
        missing = [n for n, h_ in want.items() if h_ not in rows]
        if not missing or time.time() > deadline:
            break
        time.sleep(2)
    for name, h_ in want.items():
        row = rows.get(h_)
        check(
            f"stored: {name}", row is not None, f"{row['channel']}/{row['camera_name']}" if row else "missing"
        )
    new = len(set(rows) - before)
    check("no extra items", new == len(want), f"{new} new items, expected {len(want)}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
