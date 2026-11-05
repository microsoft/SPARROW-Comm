"""Reconyx cloud image forwarding: ``POST /v1/reconyx/login`` and ``POST /v1/reconyx/images``."""

from __future__ import annotations

import base64
import binascii
import secrets
import time
from datetime import UTC, datetime
from typing import Any

import jwt
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, ValidationError

from sparrow_comm.hooks import ConfigSource, Credential, Sink
from sparrow_comm.items import Item
from sparrow_comm.util import sha256_bytes, sha256_hex


class LoginBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    Id: str = Field(validation_alias=AliasChoices("Id", "id"))
    Token: str = Field(validation_alias=AliasChoices("Token", "token"))


class ImageMetadataBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    File_name: str | None = Field(default=None, validation_alias=AliasChoices("File_name", "file_name"))
    date_time_taken: str | None = Field(
        default=None, validation_alias=AliasChoices("date_time_taken", "Date_time_taken")
    )


class ImagesBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    Token: str | None = Field(default=None, validation_alias=AliasChoices("Token", "token"))
    Camera_serial_number: str = Field(
        validation_alias=AliasChoices("Camera_serial_number", "camera_serial_number")
    )
    Image: str = Field(validation_alias=AliasChoices("Image", "image"))
    Image_group: str | None = Field(default=None, validation_alias=AliasChoices("Image_group", "image_group"))
    Metadata: ImageMetadataBody | None = Field(
        default=None, validation_alias=AliasChoices("Metadata", "metadata")
    )


class LoginResponse(BaseModel):
    token: str
    message: str = "ok"


def parse_project_login(id_field: str) -> int | None:
    """``proj_<int>`` to the project id; shared with the FTPS username convention."""
    id_field = (id_field or "").strip()
    if not id_field.startswith("proj_"):
        return None
    try:
        return int(id_field[5:])
    except ValueError:
        return None


def check_credential(cred: Credential | None, raw_token: str | None) -> bool:
    if cred is None or not raw_token:
        return False
    return secrets.compare_digest(sha256_hex(raw_token.strip()), str(cred.key_hash))


def parse_captured_at(raw: str | None) -> datetime | None:
    """Reconyx timestamp to naive UTC; naive input is taken as UTC."""
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if dt.tzinfo is not None:
            dt = dt.astimezone(UTC).replace(tzinfo=None)
        return dt
    return None


def make_reconyx_router(
    config: ConfigSource,
    sink: Sink,
    jwt_secret: str,
    jwt_ttl_seconds: int = 24 * 60 * 60,
    max_body_bytes: int = 10 * 1024 * 1024,
    prefix: str = "/v1/reconyx",
) -> APIRouter:
    """Build the Reconyx router. An empty ``jwt_secret`` makes both routes answer 503."""
    router = APIRouter(prefix=prefix)

    def not_configured() -> HTTPException:
        return HTTPException(503, "Reconyx ingest not configured")

    def verify(token: str) -> dict[str, Any]:
        if not jwt_secret:
            raise not_configured()
        if not token or not token.strip():
            raise HTTPException(401, "Missing api_key")
        try:
            payload = jwt.decode(token.strip(), jwt_secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError as e:
            raise HTTPException(401, "Token expired") from e
        except jwt.InvalidTokenError as e:
            raise HTTPException(401, "Invalid token") from e
        try:
            key_id = int(payload.get("key_id") or 0)
            project_id = int(payload.get("project_id") or 0)
        except (TypeError, ValueError):
            key_id = project_id = 0
        if not key_id or not project_id:
            raise HTTPException(401, "Invalid token payload")
        if not config.reconyx_key_authorized(key_id, project_id):
            raise HTTPException(401, "Unauthorized")
        return payload

    @router.post("/login", response_model=LoginResponse)
    def login(body: LoginBody):
        # One message for every failure so callers cannot enumerate projects or keys.
        project_id = parse_project_login(body.Id)
        cred = config.reconyx_key(project_id) if project_id is not None else None
        if not check_credential(cred, body.Token):
            raise HTTPException(401, "id and token combination is invalid")
        config.mark_reconyx_key_used(cred.id)
        if not jwt_secret:
            raise not_configured()
        now = int(time.time())
        payload = {
            "project_id": int(cred.project_id),
            "key_id": int(cred.id),
            "iat": now,
            "exp": now + jwt_ttl_seconds,
        }
        return LoginResponse(token=jwt.encode(payload, jwt_secret, algorithm="HS256"))

    @router.post("/images", status_code=200)
    async def images(request: Request, api_key: str | None = Header(default=None, alias="api_key")):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                too_big = int(content_length) > max_body_bytes
            except ValueError:
                too_big = False
            if too_big:
                raise HTTPException(413, "Image payload too large")
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > max_body_bytes:
                raise HTTPException(413, "Image payload too large")
        try:
            body = ImagesBody.model_validate_json(bytes(raw))
        except ValidationError as e:
            details = e.errors(include_url=False, include_input=False)
            if any(err.get("type") == "json_invalid" for err in details):
                raise HTTPException(400, "Body must be valid JSON") from e
            raise HTTPException(422, details) from e

        payload = await run_in_threadpool(verify, (api_key or body.Token or "").strip())
        project_id = int(payload["project_id"])

        serial = (body.Camera_serial_number or "").strip()
        if not serial:
            raise HTTPException(400, "Camera_serial_number required")
        try:
            data = base64.b64decode(body.Image, validate=True)
        except (binascii.Error, ValueError) as e:
            raise HTTPException(400, "Image is not valid base64") from e
        if not data:
            raise HTTPException(400, "Image is empty")

        sha = sha256_bytes(data)
        meta = body.Metadata or ImageMetadataBody()
        original = (meta.File_name or f"{serial}_{sha[:8]}.jpg").strip()[:240]
        try:
            res = await run_in_threadpool(
                sink.commit,
                Item(
                    kind="image",
                    channel="reconyx",
                    project_id=project_id,
                    data=data,
                    sha256=sha,
                    name=f"{sha}.jpg",
                    original_name=original,
                    camera_name=serial,
                    captured_at=parse_captured_at(meta.date_time_taken),
                    extra={"image_group": body.Image_group},
                ),
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        return {"200": 1, "image_id": res.id}

    return router
