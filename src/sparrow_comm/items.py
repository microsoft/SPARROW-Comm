"""The unit of work every receive channel hands to a :class:`~sparrow_comm.hooks.Sink`."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

Kind = Literal["image", "audio", "video"]
Channel = Literal["device", "reconyx", "imap", "ftps"]


@dataclass(frozen=True)
class Item:
    """One received file plus everything the channel knows about it.

    ``name`` is filesystem-safe; ``original_name`` is what the sender supplied (display only).
    ``captured_at`` is naive UTC. ``extra`` carries channel-specific fields:

    - device image: ``idempotency_key``
    - device audio: ``label``, ``confidence``, ``detected_at``, ``idempotency_key``
    - reconyx: ``image_group``
    - imap: ``msg_uid``, ``subject``
    """

    kind: Kind
    channel: Channel
    project_id: int
    data: bytes
    sha256: str
    name: str
    original_name: str | None = None
    device_id: int | None = None
    unit_id: str | None = None
    camera_name: str | None = None
    captured_at: datetime | None = None
    detections: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CommitResult:
    """Returned by :meth:`Sink.commit`. ``created`` is False when the sink already held the item."""

    id: int | str
    created: bool = True
