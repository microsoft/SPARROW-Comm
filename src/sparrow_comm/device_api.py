"""Device API: onboarding, image/audio uploads, metrics and settings (Studio ``/v1`` compatible)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from sparrow_comm.hooks import Device, DeviceRegistry, Sink
from sparrow_comm.items import Item
from sparrow_comm.util import parse_iso_datetime, safe_filename, sha256_bytes, sha256_hex


class OnboardingRequest(BaseModel):
    unit_id: str


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _has_person(detections: list[dict[str, Any]]) -> bool:
    return any(str(d.get("label", "")).strip().lower() == "person" for d in detections if isinstance(d, dict))


def _extract_metrics(metric_type: str, payload: dict[str, Any]) -> tuple[float | None, float | None]:
    """Best-effort battery/CPU-temperature extraction, including legacy firmware field names."""
    battery = temp = None
    try:
        if metric_type == "system":
            battery = (
                payload.get("battery_voltage")
                or payload.get("vedirect_battery_voltage")
                or (payload.get("battery") or {}).get("voltage")
            )
            temp = (
                payload.get("cpu_temp_c")
                or payload.get("cpu_temperature")
                or payload.get("temperature_celsius")
                or payload.get("bme688_temperature_celsius")
            )
        elif metric_type == "starlink":
            battery = (payload.get("status") or {}).get("battery_voltage")
        battery = float(battery) if battery is not None else None
        temp = float(temp) if temp is not None else None
    except (TypeError, ValueError, AttributeError):
        return None, None
    return battery, temp


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


def make_device_router(registry: DeviceRegistry, sink: Sink, prefix: str = "/v1") -> APIRouter:
    """Build the router. Mount it with ``app.include_router(make_device_router(...))``."""
    router = APIRouter(prefix=prefix)

    async def authenticate(api_key: str | None, unit_id: str | None) -> Device:
        key = (api_key or "").strip()
        unit = (unit_id or "").strip()
        if not key:
            raise HTTPException(401, "Missing API key")
        if not unit:
            raise HTTPException(401, "Missing unit_id")
        device = await run_in_threadpool(registry.device_by_key_hash, sha256_hex(key))
        if device is None:
            raise HTTPException(401, "Invalid API key")
        if (device.unit_id or "").strip() != unit:
            raise HTTPException(401, "Unit ID does not match key")
        return device

    async def commit(item: Item):
        try:
            return await run_in_threadpool(sink.commit, item)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    # --- onboarding -------------------------------------------------------------------------------

    @router.post("/onboarding")
    async def onboarding(
        body: OnboardingRequest,
        x_api_key: str | None = Header(None),
        x_email: str | None = Header(None),
    ):
        email = (x_email or "").strip().lower()
        if not email:
            raise HTTPException(401, "Missing X-Email header")
        unit_id = (body.unit_id or "").strip()
        if not unit_id:
            raise HTTPException(400, "Missing unit_id")
        key = (x_api_key or "").strip()
        if not key:
            raise HTTPException(401, "Missing X-API-Key header")
        key_hash = sha256_hex(key)
        ok = await run_in_threadpool(registry.onboarding_key_by_hash, key_hash)
        if ok is None:
            raise HTTPException(401, "Invalid onboarding key")
        if (ok.created_by_email or "").strip().lower() != email:
            raise HTTPException(401, "Email does not match key")
        if ok.consumed_at is not None:
            if ok.consumed_by_device_id is None:
                raise HTTPException(409, "Key already consumed")
            existing = await run_in_threadpool(registry.device_by_key_hash, key_hash)
            if existing is not None and (existing.unit_id or "").strip() == unit_id:
                return {
                    "ok": True,
                    "project_id": existing.project_id,
                    "device_id": existing.device_id,
                    "unit_id": unit_id,
                    "idempotent": True,
                }
            raise HTTPException(409, "Key already bound to a different unit_id")
        can = await run_in_threadpool(registry.issuer_can_manage, ok.project_id, ok.created_by_user_id)
        if not can:
            raise HTTPException(403, "Key issuer no longer has manage access to the project")
        device_id = await run_in_threadpool(registry.consume_onboarding_key, ok, unit_id)
        return {"ok": True, "project_id": ok.project_id, "device_id": device_id, "unit_id": unit_id}

    # --- uploads ----------------------------------------------------------------------------------

    @router.post("/uploads/image")
    async def upload_image(
        file: UploadFile = File(...),
        metadata: str = Form(...),
        auth_key: str | None = Form(None),
        unique_id: str | None = Form(None),
        x_api_key: str | None = Header(None),
        x_unit_id: str | None = Header(None),
        idempotency_key: str | None = Header(None),
    ):
        device = await authenticate(x_api_key or auth_key, x_unit_id or unique_id)
        try:
            meta = json.loads(metadata) if metadata else {}
            if not isinstance(meta, dict):
                raise ValueError
        except ValueError as e:
            raise HTTPException(400, "metadata must be valid JSON") from e
        data = await file.read()
        if not data:
            raise HTTPException(400, "Empty image file")
        image_name = str(meta.get("image_name") or file.filename or "image.jpg").strip()
        captured_at = parse_iso_datetime(meta.get("captured_at")) or _now()
        detections = meta.get("detections") or []
        if not isinstance(detections, list):
            raise HTTPException(400, "detections must be a list")
        if _has_person(detections):
            return {"ok": True, "discarded": True, "reason": "privacy_person"}
        res = await commit(
            Item(
                kind="image",
                channel="device",
                project_id=device.project_id,
                device_id=device.device_id,
                unit_id=device.unit_id,
                camera_name=device.unit_id,
                data=data,
                sha256=sha256_bytes(data),
                name=safe_filename(image_name, "image.jpg"),
                original_name=image_name,
                captured_at=captured_at,
                detections=detections,
                extra={"idempotency_key": idempotency_key},
            )
        )
        return JSONResponse(
            status_code=201,
            content={
                "ok": True,
                "image_id": res.id,
                "project_id": device.project_id,
                "device_id": device.device_id,
                "unit_id": device.unit_id,
                "discarded": False,
                "detection_count": len(detections),
            },
        )

    @router.post("/uploads", include_in_schema=False)
    async def upload_legacy(
        file: UploadFile = File(...),
        auth_key: str = Form(...),
        unique_id: str = Form(...),
        image_name: str = Form(...),
        detection: str = Form(""),
        confidence: float = Form(0.0),
        date: str = Form(""),
    ):
        device = await authenticate(auth_key, unique_id)
        data = await file.read()
        if not data:
            raise HTTPException(400, "Empty image file")
        captured_at = (
            parse_iso_datetime(date)
            or parse_iso_datetime(date.replace(" ", "T") + "Z" if date else None)
            or _now()
        )
        detections = (
            [{"label": detection or "unknown", "confidence": confidence, "bbox": [0, 0, 0, 0]}]
            if detection
            else []
        )
        if _has_person(detections):
            return {"ok": True, "discarded": True, "reason": "privacy_person"}
        res = await commit(
            Item(
                kind="image",
                channel="device",
                project_id=device.project_id,
                device_id=device.device_id,
                unit_id=device.unit_id,
                camera_name=device.unit_id,
                data=data,
                sha256=sha256_bytes(data),
                name=safe_filename(image_name, "image.jpg"),
                original_name=image_name,
                captured_at=captured_at,
                detections=detections,
            )
        )
        return JSONResponse(
            status_code=201,
            content={
                "ok": True,
                "image_id": res.id,
                "project_id": device.project_id,
                "device_id": device.device_id,
                "unit_id": device.unit_id,
            },
        )

    async def upload_audio(
        file: UploadFile = File(...),
        metadata: str = Form("{}"),
        auth_key: str | None = Form(None),
        unique_id: str | None = Form(None),
        x_api_key: str | None = Header(None),
        x_unit_id: str | None = Header(None),
        idempotency_key: str | None = Header(None),
    ):
        device = await authenticate(x_api_key or auth_key, x_unit_id or unique_id)
        try:
            meta = json.loads(metadata) if metadata else {}
            if not isinstance(meta, dict):
                raise ValueError
        except ValueError as e:
            raise HTTPException(400, "metadata must be valid JSON") from e
        data = await file.read()
        if not data:
            raise HTTPException(400, "Empty audio file")
        audio_name = str(meta.get("audio_name") or file.filename or "audio.wav").strip()
        detected_at = parse_iso_datetime(meta.get("detected_at"))
        conf = meta.get("confidence")
        try:
            conf = float(conf) if conf is not None else None
        except (TypeError, ValueError) as e:
            raise HTTPException(400, "confidence must be a number") from e
        res = await commit(
            Item(
                kind="audio",
                channel="device",
                project_id=device.project_id,
                device_id=device.device_id,
                unit_id=device.unit_id,
                camera_name=device.unit_id,
                data=data,
                sha256=sha256_bytes(data),
                name=safe_filename(audio_name, "audio.wav"),
                original_name=audio_name,
                captured_at=detected_at or _now(),
                extra={
                    "label": meta.get("label") or None,
                    "confidence": conf,
                    "detected_at": detected_at,
                    "idempotency_key": idempotency_key,
                },
            )
        )
        return JSONResponse(
            status_code=201,
            content={
                "ok": True,
                "audio_id": res.id,
                "project_id": device.project_id,
                "device_id": device.device_id,
            },
        )

    router.add_api_route("/uploads/audio", upload_audio, methods=["POST"])
    router.add_api_route("/audio_uploads", upload_audio, methods=["POST"], include_in_schema=False)

    # --- metrics ----------------------------------------------------------------------------------

    def metrics_route(metric_type: Literal["system", "starlink"]):
        async def handler(
            request: Request,
            x_api_key: str | None = Header(None),
            x_unit_id: str | None = Header(None),
        ):
            payload = await _json_body(request)
            device = await authenticate(
                x_api_key or payload.get("auth_key"), x_unit_id or payload.get("unique_id")
            )
            if not payload:
                raise HTTPException(400, "JSON body required")
            reading_ts = parse_iso_datetime(payload.get("timestamp")) or _now()
            battery, temp = _extract_metrics(metric_type, payload)
            reading_id = await run_in_threadpool(
                registry.record_metrics, device, metric_type, reading_ts, battery, temp, payload
            )
            return {"ok": True, "reading_id": reading_id, "metric_type": metric_type}

        return handler

    system_metrics = metrics_route("system")
    starlink_metrics = metrics_route("starlink")
    router.add_api_route("/metrics/system", system_metrics, methods=["POST"])
    router.add_api_route("/system_metrics", system_metrics, methods=["POST"], include_in_schema=False)
    router.add_api_route("/metrics/starlink", starlink_metrics, methods=["POST"])
    router.add_api_route("/metrics", starlink_metrics, methods=["POST"], include_in_schema=False)

    # --- settings ---------------------------------------------------------------------------------

    def settings_route(build):
        # Legacy firmware POSTs auth_key + unique_id in a JSON body; newer firmware uses headers.
        async def handler(
            request: Request,
            x_api_key: str | None = Header(None),
            x_unit_id: str | None = Header(None),
        ):
            body = await _json_body(request)
            device = await authenticate(x_api_key or body.get("auth_key"), x_unit_id or body.get("unique_id"))
            if build is None:
                return {"save_person": "no"}
            s = await run_in_threadpool(registry.device_settings, device.device_id) or {}
            return build(s)

        return handler

    def schedule(s):
        return {
            "start_time": s.get("sleep_start_utc", "20:15"),
            "end_time": s.get("sleep_end_utc", "20:30"),
            "timezone": s.get("sleep_timezone", "UTC"),
        }

    def audio(s):
        return {
            "mode": s.get("audio_mode", "threshold"),
            "SAMPLE_RATE": int(s.get("audio_sample_rate", 44100)),
            "MONITOR_DURATION": int(s.get("audio_monitor_duration", 1)),
            "RECORD_DURATION": int(s.get("audio_record_duration", 2)),
            "THRESHOLD": int(s.get("audio_threshold", 2500)),
            "SCHEDULE_INTERVAL": int(s.get("audio_schedule_interval", 60)),
            "SCHEDULE_DURATION": int(s.get("audio_schedule_duration", 10)),
        }

    def model(s):
        return {
            "selected_model": s.get("model_name", "AI4GAmazonClassification"),
            "detection_threshold": float(s.get("model_detection_threshold", 0.4)),
            "classification_enabled": bool(s.get("model_classification_enabled", True)),
            "keep_blanks": bool(s.get("model_keep_blanks", False)),
        }

    def video(s):
        urls = [s.get(f"video_url{i}") for i in range(1, 5)]
        return {"urls": [u for u in urls if u], "selected_model": s.get("video_model") or ""}

    def alerts(s):
        return {
            "enabled": bool(s.get("alerts_enabled", False)),
            "alerts": s.get("alerts_labels", []),
            "recipients": s.get("alerts_recipients", []),
        }

    for path, legacy, build in [
        ("schedule", "get_schedule", schedule),
        ("audio", "get_scheduleaudio", audio),
        ("model", "model_settings", model),
        ("video", "video_settings", video),
        ("alerts", "alert_settings", alerts),
        ("privacy", "privacy_settings", None),
    ]:
        h = settings_route(build)
        router.add_api_route(f"/settings/{path}", h, methods=["POST"])
        router.add_api_route(f"/{legacy}", h, methods=["POST"], include_in_schema=False)

    return router
