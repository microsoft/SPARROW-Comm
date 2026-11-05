"""Host hooks. The package owns receive logic; everything host-specific goes through these.

All hook methods are synchronous. Async routes call them in a worker thread.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from sparrow_comm.items import CommitResult, Item


@dataclass(frozen=True)
class Device:
    project_id: int
    device_id: int
    unit_id: str


@dataclass(frozen=True)
class OnboardingKey:
    id: int
    project_id: int
    key_hash: str
    key_prefix: str
    created_by_email: str
    created_by_user_id: int
    consumed_at: datetime | None = None
    consumed_by_device_id: int | None = None


@dataclass(frozen=True)
class Credential:
    """An FTPS password or Reconyx token, stored as a sha256 hex digest."""

    id: int
    project_id: int
    key_hash: str


@dataclass(frozen=True)
class ImapAccount:
    project_id: int
    address: str
    password: str
    last_uid: int = 0


@runtime_checkable
class Sink(Protocol):
    def seen(self, item: Item) -> bool:
        """True if this item was already committed (pull channels skip it)."""
        ...

    def commit(self, item: Item) -> CommitResult:
        """Store the file, then record it. Idempotent: a repeat returns the existing id.

        Raise ``ValueError`` to reject an item; the device API turns it into HTTP 400.
        """
        ...


@runtime_checkable
class DeviceRegistry(Protocol):
    def device_by_key_hash(self, key_hash: str) -> Device | None: ...

    def onboarding_key_by_hash(self, key_hash: str) -> OnboardingKey | None: ...

    def issuer_can_manage(self, project_id: int, user_id: int) -> bool: ...

    def consume_onboarding_key(self, key: OnboardingKey, unit_id: str) -> int:
        """Bind the key to a new device (whose API key is the onboarding key). Return its id."""
        ...

    def device_settings(self, device_id: int) -> dict[str, Any]:
        """Settings row keyed by Studio column names (``sleep_start_utc``, ``audio_mode``, ...)."""
        ...

    def record_metrics(
        self,
        device: Device,
        metric_type: str,
        reading_ts: datetime,
        battery_voltage: float | None,
        cpu_temp_c: float | None,
        payload: dict[str, Any],
    ) -> int: ...


@runtime_checkable
class ConfigSource(Protocol):
    def imap_accounts(self) -> list[ImapAccount]: ...

    def set_imap_last_uid(self, project_id: int, last_uid: int) -> None: ...

    def ftps_projects(self) -> list[int]: ...

    def ftps_credential(self, project_id: int) -> Credential | None: ...

    def record_ftps_usage(self, credential_id: int) -> None: ...

    def reconyx_key(self, project_id: int) -> Credential | None:
        """The project's active Reconyx key."""
        ...

    def mark_reconyx_key_used(self, key_id: int) -> None: ...

    def reconyx_key_authorized(self, key_id: int, project_id: int) -> bool:
        """Re-checked on every image: key still active, bound to the project, project accepts uploads."""
        ...
