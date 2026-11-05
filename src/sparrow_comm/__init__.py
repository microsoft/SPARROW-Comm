"""Receivers for SPARROW field data: device API, Reconyx, IMAP e-mail and FTPS."""

from importlib.metadata import PackageNotFoundError, version

from sparrow_comm.hooks import (
    ConfigSource,
    Credential,
    Device,
    DeviceRegistry,
    ImapAccount,
    OnboardingKey,
    Sink,
)
from sparrow_comm.items import CommitResult, Item

try:
    __version__ = version("sparrow-comm")
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0"

__all__ = [
    "CommitResult",
    "ConfigSource",
    "Credential",
    "Device",
    "DeviceRegistry",
    "ImapAccount",
    "Item",
    "OnboardingKey",
    "Sink",
    "__version__",
]
