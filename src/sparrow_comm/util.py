from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff"}
VIDEO_EXT = {".mp4"}


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def parse_iso_datetime(value: str | None) -> datetime | None:
    """ISO 8601 to naive UTC; ``None`` when absent or unparseable."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def safe_filename(name: str | None, default: str = "") -> str:
    """Keep alphanumerics and ``-_.``; spaces become underscores."""
    out = "".join(c for c in (name or "") if c.isalnum() or c in ("-", "_", ".", " ")).strip()
    return out.replace(" ", "_") or default


def atomic_write(path: Path, data: bytes) -> None:
    """Write via ``.tmp`` + fsync + rename so a crash never leaves a truncated file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def decrypt_app_password(app_secret_key: str, ciphertext: bytes | str) -> str:
    """Fernet-decrypt an IMAP app password (Studio stores them this way)."""
    from cryptography.fernet import Fernet

    if not app_secret_key:
        raise RuntimeError("APP_SECRET_KEY is not set")
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode("utf-8")
    return Fernet(app_secret_key.encode("utf-8")).decrypt(ciphertext).decode("utf-8")
