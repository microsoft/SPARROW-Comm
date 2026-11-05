"""Standalone defaults: one SQLite file plus a directory of received files.

:class:`Store` implements :class:`~sparrow_comm.hooks.Sink`, :class:`~sparrow_comm.hooks.DeviceRegistry`
and :class:`~sparrow_comm.hooks.ConfigSource`, so a deployment without Studio can run every channel
from a single object. Hosts with their own database implement the protocols instead.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sparrow_comm.hooks import Credential, Device, ImapAccount, OnboardingKey
from sparrow_comm.items import CommitResult, Item
from sparrow_comm.util import atomic_write, safe_filename, sha256_hex

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL,
    unit_id TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS onboarding_keys (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    created_by_email TEXT NOT NULL,
    created_by_user_id INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    consumed_by_device_id INTEGER
);
CREATE TABLE IF NOT EXISTS device_settings (
    device_id INTEGER PRIMARY KEY,
    settings TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL,
    device_id INTEGER NOT NULL,
    metric_type TEXT NOT NULL,
    reading_ts TEXT NOT NULL,
    battery_voltage REAL,
    cpu_temp_c REAL,
    payload TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS imap_accounts (
    project_id INTEGER PRIMARY KEY,
    address TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    last_uid INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ftps_credentials (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS reconyx_keys (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL,
    key_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    channel TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    original_name TEXT,
    device_id INTEGER,
    unit_id TEXT,
    camera_name TEXT,
    captured_at TEXT,
    detections TEXT NOT NULL,
    extra TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE (project_id, kind, sha256)
);
"""


def _now() -> str:
    return datetime.now(UTC).replace(tzinfo=None).isoformat(timespec="seconds")


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class Store:
    """SQLite + filesystem implementation of all three hooks.

    Files land at ``<data_dir>/<project>/<kind>/<YYYY-MM-DD>/<sha[:16]>__<name>``; the file is written
    (atomically) before its row, so a row never points at a missing file. Items are de-duplicated per
    project and kind by sha256. IMAP passwords are Fernet-encrypted with ``secret_key``.
    """

    def __init__(self, db_path: str | Path, data_dir: str | Path, secret_key: str | None = None) -> None:
        self.db_path = Path(db_path)
        self.data_dir = Path(data_dir)
        self.secret_key = secret_key
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    # --- Sink ------------------------------------------------------------------------------------

    def _existing(self, c: sqlite3.Connection, item: Item) -> int | None:
        row = c.execute(
            "SELECT id FROM items WHERE project_id=? AND kind=? AND sha256=?",
            (item.project_id, item.kind, item.sha256),
        ).fetchone()
        return row["id"] if row else None

    def seen(self, item: Item) -> bool:
        with self._conn() as c:
            return self._existing(c, item) is not None

    def commit(self, item: Item) -> CommitResult:
        with self._conn() as c:
            existing = self._existing(c, item)
        if existing is not None:
            return CommitResult(existing, created=False)
        day = (item.captured_at or datetime.now(UTC)).strftime("%Y-%m-%d")
        name = safe_filename(item.name, item.kind)
        rel = Path(str(item.project_id), item.kind, day, f"{item.sha256[:16]}__{name}")
        atomic_write(self.data_dir / rel, item.data)
        with self._conn() as c:
            try:
                cur = c.execute(
                    "INSERT INTO items (project_id, kind, channel, sha256, path, name, original_name,"
                    " device_id, unit_id, camera_name, captured_at, detections, extra, received_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        item.project_id,
                        item.kind,
                        item.channel,
                        item.sha256,
                        rel.as_posix(),
                        name,
                        item.original_name,
                        item.device_id,
                        item.unit_id,
                        item.camera_name,
                        item.captured_at.isoformat() if item.captured_at else None,
                        json.dumps(item.detections),
                        json.dumps(item.extra, default=str),
                        _now(),
                    ),
                )
            except sqlite3.IntegrityError:
                # A concurrent commit of the same bytes won; it wrote the same path.
                return CommitResult(self._existing(c, item), created=False)
            return CommitResult(cur.lastrowid, created=True)

    def items(self, project_id: int | None = None) -> list[dict[str, Any]]:
        with self._conn() as c:
            if project_id is None:
                rows = c.execute("SELECT * FROM items ORDER BY id").fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM items WHERE project_id=? ORDER BY id", (project_id,)
                ).fetchall()
        return [dict(r) for r in rows]

    # --- DeviceRegistry --------------------------------------------------------------------------

    def device_by_key_hash(self, key_hash: str) -> Device | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT id, project_id, unit_id FROM devices WHERE key_hash=?", (key_hash,)
            ).fetchone()
        return Device(row["project_id"], row["id"], row["unit_id"]) if row else None

    def onboarding_key_by_hash(self, key_hash: str) -> OnboardingKey | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM onboarding_keys WHERE key_hash=?", (key_hash,)).fetchone()
        if row is None:
            return None
        return OnboardingKey(
            id=row["id"],
            project_id=row["project_id"],
            key_hash=row["key_hash"],
            key_prefix=row["key_prefix"],
            created_by_email=row["created_by_email"],
            created_by_user_id=row["created_by_user_id"],
            consumed_at=_dt(row["consumed_at"]),
            consumed_by_device_id=row["consumed_by_device_id"],
        )

    def issuer_can_manage(self, project_id: int, user_id: int) -> bool:
        # Standalone mode has no user accounts; whoever can run the CLI manages every project.
        return True

    def consume_onboarding_key(self, key: OnboardingKey, unit_id: str) -> int:
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                "SELECT consumed_by_device_id FROM onboarding_keys WHERE id=? AND consumed_at IS NOT NULL",
                (key.id,),
            ).fetchone()
            if row is not None:
                return int(row["consumed_by_device_id"])
            now = _now()
            cur = c.execute(
                "INSERT INTO devices (project_id, unit_id, key_hash, created_at) VALUES (?,?,?,?)",
                (key.project_id, unit_id, key.key_hash, now),
            )
            device_id = int(cur.lastrowid)
            c.execute(
                "UPDATE onboarding_keys SET consumed_at=?, consumed_by_device_id=? WHERE id=?",
                (now, device_id, key.id),
            )
            return device_id

    def device_settings(self, device_id: int) -> dict[str, Any]:
        with self._conn() as c:
            row = c.execute("SELECT settings FROM device_settings WHERE device_id=?", (device_id,)).fetchone()
        return json.loads(row["settings"]) if row else {}

    def record_metrics(
        self,
        device: Device,
        metric_type: str,
        reading_ts: datetime,
        battery_voltage: float | None,
        cpu_temp_c: float | None,
        payload: dict[str, Any],
    ) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO metrics (project_id, device_id, metric_type, reading_ts, battery_voltage,"
                " cpu_temp_c, payload, received_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    device.project_id,
                    device.device_id,
                    metric_type,
                    reading_ts.isoformat(),
                    battery_voltage,
                    cpu_temp_c,
                    json.dumps(payload, default=str),
                    _now(),
                ),
            )
            return int(cur.lastrowid)

    # --- DeviceRegistry admin --------------------------------------------------------------------

    def issue_onboarding_key(self, project_id: int, email: str, user_id: int = 0) -> str:
        """Create a one-time onboarding key and return it. Only its hash is stored."""
        key = secrets.token_urlsafe(32)
        with self._conn() as c:
            c.execute(
                "INSERT INTO onboarding_keys (project_id, key_hash, key_prefix, created_by_email,"
                " created_by_user_id, created_at) VALUES (?,?,?,?,?,?)",
                (project_id, sha256_hex(key), key[:8], email.strip().lower(), user_id, _now()),
            )
        return key

    def set_device_settings(self, device_id: int, settings: dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO device_settings (device_id, settings) VALUES (?, ?)"
                " ON CONFLICT(device_id) DO UPDATE SET settings=excluded.settings",
                (device_id, json.dumps(settings)),
            )

    def devices(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT id, project_id, unit_id, created_at FROM devices")]

    # --- ConfigSource ----------------------------------------------------------------------------

    def imap_accounts(self) -> list[ImapAccount]:
        from sparrow_comm.util import decrypt_app_password

        with self._conn() as c:
            rows = c.execute("SELECT * FROM imap_accounts ORDER BY project_id").fetchall()
        return [
            ImapAccount(
                project_id=r["project_id"],
                address=r["address"],
                password=decrypt_app_password(self.secret_key or "", r["password_enc"]),
                last_uid=r["last_uid"],
            )
            for r in rows
        ]

    def set_imap_last_uid(self, project_id: int, last_uid: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE imap_accounts SET last_uid=? WHERE project_id=?", (last_uid, project_id))

    def ftps_projects(self) -> list[int]:
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT project_id FROM ftps_credentials ORDER BY project_id")]

    def ftps_credential(self, project_id: int) -> Credential | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT id, key_hash FROM ftps_credentials WHERE project_id=?", (project_id,)
            ).fetchone()
        return Credential(row["id"], project_id, row["key_hash"]) if row else None

    def record_ftps_usage(self, credential_id: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE ftps_credentials SET last_used_at=? WHERE id=?", (_now(), credential_id))

    def reconyx_key(self, project_id: int) -> Credential | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT id, key_hash FROM reconyx_keys WHERE project_id=? AND active=1"
                " ORDER BY id DESC LIMIT 1",
                (project_id,),
            ).fetchone()
        return Credential(row["id"], project_id, row["key_hash"]) if row else None

    def mark_reconyx_key_used(self, key_id: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE reconyx_keys SET last_used_at=? WHERE id=?", (_now(), key_id))

    def reconyx_key_authorized(self, key_id: int, project_id: int) -> bool:
        with self._conn() as c:
            row = c.execute(
                "SELECT 1 FROM reconyx_keys WHERE id=? AND project_id=? AND active=1", (key_id, project_id)
            ).fetchone()
        return row is not None

    # --- ConfigSource admin ----------------------------------------------------------------------

    def set_imap_account(self, project_id: int, address: str, password: str) -> None:
        from cryptography.fernet import Fernet

        if not self.secret_key:
            raise RuntimeError("A secret key is required to store IMAP passwords (SPARROW_COMM_SECRET_KEY)")
        enc = Fernet(self.secret_key.encode()).encrypt(password.encode()).decode()
        with self._conn() as c:
            c.execute(
                "INSERT INTO imap_accounts (project_id, address, password_enc) VALUES (?,?,?)"
                " ON CONFLICT(project_id) DO UPDATE SET address=excluded.address,"
                " password_enc=excluded.password_enc, last_uid=0",
                (project_id, address.strip(), enc),
            )

    def set_ftps_password(self, project_id: int, password: str | None = None) -> str:
        """Set (or generate) the project's FTPS password and return it. Login user is ``proj_<id>``."""
        password = password or secrets.token_urlsafe(18)
        with self._conn() as c:
            c.execute(
                "INSERT INTO ftps_credentials (project_id, key_hash) VALUES (?, ?)"
                " ON CONFLICT(project_id) DO UPDATE SET key_hash=excluded.key_hash",
                (project_id, sha256_hex(password)),
            )
        return password

    def issue_reconyx_key(self, project_id: int) -> str:
        """Create a Reconyx token for the project, deactivating earlier ones, and return it."""
        token = secrets.token_urlsafe(24)
        with self._conn() as c:
            c.execute("UPDATE reconyx_keys SET active=0 WHERE project_id=?", (project_id,))
            c.execute(
                "INSERT INTO reconyx_keys (project_id, key_hash) VALUES (?, ?)",
                (project_id, sha256_hex(token)),
            )
        return token
