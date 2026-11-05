"""FTPS channel: a TLS FTP server that drops uploads into per-project staging dirs, plus a poller
that turns staged files into Items.

The server half needs the ``ftps`` extra (``pyftpdlib``, ``pyOpenSSL``).
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import os
import re
import secrets
import socket
import time
from pathlib import Path
from typing import Any

from sparrow_comm.hooks import ConfigSource, Sink
from sparrow_comm.items import Item
from sparrow_comm.util import IMAGE_EXT, VIDEO_EXT, safe_filename, sha256_bytes, sha256_hex

log = logging.getLogger("sparrow_comm.ftps")

ALLOWED_EXT = IMAGE_EXT | VIDEO_EXT
MIN_AGE_SECONDS = 5

_CAMERA_NAME_PATTERNS = (
    re.compile(r"^[0-9A-Fa-f]+__([A-Za-z0-9][A-Za-z0-9_-]*?)_\d{2}_\d{14}\b"),
    re.compile(r"^([A-Za-z0-9][A-Za-z0-9_-]*?)_\d{2}_\d{14}\b"),  # Reolink: name_channel_timestamp
    re.compile(r"^([A-Za-z0-9][A-Za-z0-9_-]*?)_\d{8,14}\b"),  # name_timestamp
    re.compile(r"\bfrom\b\s*[:\-]?\s*([A-Za-z0-9_-]+)", re.IGNORECASE),
)


def camera_name_from_filename(fname: str) -> str:
    stem = os.path.splitext(fname)[0]
    for rx in _CAMERA_NAME_PATTERNS:
        m = rx.search(stem)
        if m:
            return m.group(1)
    return "Unknown"


def validate_credential(config: ConfigSource, username: str, password: str) -> bool:
    """``proj_<id>`` + the project's FTPS password (sha256-compared). Any error means no."""
    if not username.startswith("proj_"):
        return False
    try:
        project_id = int(username[5:])
        cred = config.ftps_credential(project_id)
        if cred is None:
            return False
        if not secrets.compare_digest(sha256_hex(password), str(cred.key_hash)):
            return False
        config.record_ftps_usage(cred.id)
        return True
    except Exception:
        return False


# --- poller -------------------------------------------------------------------------------------


def poll_project(
    sink: Sink,
    staging_dir: str | Path,
    project_id: int,
    min_age_seconds: float = MIN_AGE_SECONDS,
    max_file_bytes: int | None = None,
) -> int:
    """Commit every settled file under ``staging_dir/<project_id>``. Returns the number committed.

    The source file is removed only after the sink accepted it (or already had it), so a failed
    commit is retried on the next poll.
    """
    src_dir = Path(staging_dir) / str(project_id)
    if not src_dir.is_dir():
        return 0
    now = time.time()
    committed = 0
    for dirpath, _dirs, files in os.walk(src_dir):
        for fname in files:
            path = Path(dirpath) / fname
            ext = path.suffix.lower()
            if ext not in ALLOWED_EXT or not path.is_file():
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            if now - st.st_mtime < min_age_seconds:
                continue
            if max_file_bytes is not None and st.st_size > max_file_bytes:
                log.warning("project=%s dropping oversize file=%s bytes=%s", project_id, path, st.st_size)
                path.unlink(missing_ok=True)
                continue
            try:
                data = path.read_bytes()
            except OSError:
                log.warning("project=%s could not read file=%s", project_id, path)
                continue
            item = Item(
                kind="video" if ext in VIDEO_EXT else "image",
                channel="ftps",
                project_id=project_id,
                data=data,
                sha256=sha256_bytes(data),
                name=safe_filename(fname, "image"),
                original_name=fname,
                camera_name=camera_name_from_filename(fname),
            )
            if not sink.seen(item):
                try:
                    sink.commit(item)
                    committed += 1
                except Exception:
                    log.exception("project=%s commit failed file=%s", project_id, path)
                    continue
            try:
                path.unlink()
            except OSError:
                log.warning("project=%s committed but could not remove file=%s", project_id, path)
    for dirpath, _dirs, _files in os.walk(src_dir, topdown=False):
        if Path(dirpath) != src_dir and not os.listdir(dirpath):
            with contextlib.suppress(OSError):
                os.rmdir(dirpath)
    return committed


def poll_once(sink: Sink, config: ConfigSource, staging_dir: str | Path, **kwargs: Any) -> int:
    total = 0
    for project_id in config.ftps_projects():
        try:
            total += poll_project(sink, staging_dir, int(project_id), **kwargs)
        except Exception:
            log.exception("project=%s ftps poll failed", project_id)
    return total


# --- server -------------------------------------------------------------------------------------


def resolve_masquerade_address(raw: str | None) -> str | None:
    """PASV replies need a numeric IPv4; resolve a hostname once at startup."""
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        ipaddress.IPv4Address(raw)
        return raw
    except ipaddress.AddressValueError:
        pass
    try:
        return socket.gethostbyname(raw)
    except socket.gaierror as e:
        log.error("masquerade host=%s could not resolve: %s", raw, e)
        return raw


def require_tls_files(certfile: str, keyfile: str) -> None:
    missing = [p for p in (certfile, keyfile) if not os.path.isfile(p)]
    if missing:
        raise FileNotFoundError(f"FTPS TLS certificate files are required. Missing: {', '.join(missing)}")
    unreadable = [p for p in (certfile, keyfile) if not os.access(p, os.R_OK)]
    if unreadable:
        raise PermissionError(
            f"FTPS TLS certificate files must be readable. Unreadable: {', '.join(unreadable)}"
        )


class Authorizer:
    """pyftpdlib authorizer backed by a :class:`ConfigSource`. Each project is jailed to its own dir."""

    def __init__(self, config: ConfigSource, staging_dir: str | Path, perms: str = "elradfmw") -> None:
        self.config = config
        self.staging_dir = Path(staging_dir)
        self.perms = perms

    def validate_authentication(self, username, password, handler):
        from pyftpdlib.authorizers import AuthenticationFailed

        if not validate_credential(self.config, username, password):
            raise AuthenticationFailed("Invalid credentials.")

    def get_home_dir(self, username):
        home = self.staging_dir / str(int(username[5:]))
        home.mkdir(parents=True, exist_ok=True)
        return str(home)

    def has_user(self, username):
        return username.startswith("proj_")

    def has_perm(self, username, perm, path=None):
        return perm in self.perms

    def get_perms(self, username):
        return self.perms

    def get_msg_login(self, username):
        return "Welcome to SPARROW FTPS."

    def get_msg_quit(self, username):
        return "Goodbye."

    def impersonate_user(self, username, password):
        pass

    def terminate_impersonation(self, username):
        pass


def make_server(
    config: ConfigSource,
    staging_dir: str | Path,
    certfile: str,
    keyfile: str,
    bind: tuple[str, int] = ("0.0.0.0", 21),
    passive_ports: range | None = range(51000, 51051),
    masquerade_address: str | None = None,
    tls_data_required: bool = True,
    perms: str = "elradfmw",
    max_cons: int = 256,
    max_cons_per_ip: int = 10,
):
    """Build (but do not start) the FTPS server. Call ``.serve_forever()`` on the result."""
    from pyftpdlib.handlers import TLS_FTPHandler
    from pyftpdlib.servers import FTPServer

    require_tls_files(certfile, keyfile)

    class Handler(TLS_FTPHandler):
        def on_login(self, username):
            log.info("login user=%s remote=%s", username, self.remote_ip)

        def on_login_failed(self, username, password):
            log.warning("login_failed user=%s remote=%s", username, self.remote_ip)

        def on_file_received(self, file_path):
            log.info("file_received path=%s", file_path)

        def on_incomplete_file_received(self, file_path):
            log.warning("incomplete_file path=%s", file_path)

    Handler.authorizer = Authorizer(config, staging_dir, perms)
    Handler.certfile = certfile
    Handler.keyfile = keyfile
    Handler.tls_control_required = True
    Handler.tls_data_required = tls_data_required
    Handler.permit_foreign_addresses = True
    Handler.passive_ports = passive_ports
    Handler.masquerade_address = resolve_masquerade_address(masquerade_address)
    Handler.banner = "SPARROW FTPS server ready."
    server = FTPServer(bind, Handler)
    server.max_cons = max_cons
    server.max_cons_per_ip = max_cons_per_ip
    return server
