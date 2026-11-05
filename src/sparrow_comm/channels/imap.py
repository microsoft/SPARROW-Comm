"""IMAP e-mail channel: pull image attachments that camera traps e-mail to a project mailbox."""

from __future__ import annotations

import contextlib
import email
import imaplib
import logging
import os
import re
from collections.abc import Callable
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr

from sparrow_comm.hooks import ConfigSource, ImapAccount, Sink
from sparrow_comm.items import Item
from sparrow_comm.util import IMAGE_EXT, safe_filename, sha256_bytes

log = logging.getLogger("sparrow_comm.imap")

_SUBJECT_CAM_RE = re.compile(r"\bfrom\b\s*[:\-]?\s*([A-Za-z0-9_-]+)", re.IGNORECASE)

ImapFactory = Callable[[str, int], imaplib.IMAP4]


def decode_mime_header(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def camera_name_from_subject(subject: str) -> str | None:
    s = " ".join(decode_mime_header(subject).strip().split())
    m = _SUBJECT_CAM_RE.search(s)
    if not m:
        return None
    return (m.group(1) or "").strip() or None


def camera_name_for(msg: Message) -> str:
    """Subject ``... from CAM01 ...``, then the sender's display name, then ``Unknown``."""
    name, _ = parseaddr(msg.get("From", "") or "")
    return camera_name_from_subject(msg.get("Subject") or "") or (name or "").strip() or "Unknown"


def sender_address(msg: Message) -> str:
    _, addr = parseaddr(msg.get("From", "") or "")
    return (addr or "").strip().lower()


def image_attachments(msg: Message) -> list[tuple[str, bytes]]:
    """``(filename, bytes)`` for every part that has a filename and is an image by type or extension."""
    out = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        if not filename:
            continue
        ext = os.path.splitext(filename)[1].lower()
        if not (part.get_content_type() or "").startswith("image/") and ext not in IMAGE_EXT:
            continue
        payload = part.get_payload(decode=True)
        if payload:
            out.append((filename, payload))
    return out


def items_from_message(msg: Message, project_id: int, uid: int) -> list[Item]:
    """Turn one parsed message into Items (no sender check)."""
    camera = camera_name_for(msg)
    subject = decode_mime_header((msg.get("Subject") or "").strip())
    items = []
    for filename, data in image_attachments(msg):
        safe = safe_filename(filename)
        if not safe or os.path.splitext(safe)[1].lower() not in IMAGE_EXT:
            continue
        items.append(
            Item(
                kind="image",
                channel="imap",
                project_id=project_id,
                data=data,
                sha256=sha256_bytes(data),
                name=safe,
                original_name=filename or safe,
                camera_name=camera,
                extra={"msg_uid": uid, "subject": subject},
            )
        )
    return items


def poll_account(
    account: ImapAccount,
    sink: Sink,
    config: ConfigSource,
    host: str = "imap.gmail.com",
    port: int = 993,
    folder: str = "INBOX",
    max_uids: int = 200,
    imap_factory: ImapFactory = imaplib.IMAP4_SSL,
) -> int:
    """Fetch new messages for one mailbox. Returns the number of items committed.

    The UID cursor advances past every UID examined, including skipped messages. An item whose
    commit fails is logged and skipped; ``Sink.seen`` keeps reruns from duplicating the rest.
    """
    expected = account.address.strip().lower()
    last_uid = int(account.last_uid or 0)
    imap = imap_factory(host, port)
    try:
        imap.login(account.address.strip(), account.password)
        status, _ = imap.select(folder, readonly=True)
        if status != "OK":
            raise RuntimeError(f"Failed to select folder {folder}")
        criteria = f"(UID {last_uid + 1}:*)" if last_uid > 0 else "ALL"
        status, data = imap.uid("SEARCH", None, criteria)
        uids = [int(x) for x in data[0].split()] if status == "OK" and data and data[0] else []
        # "n:*" always matches the newest message, even when its UID is <= n.
        uids = sorted(u for u in uids if u > last_uid)[:max_uids]

        committed = 0
        newest = last_uid
        for uid in uids:
            newest = max(newest, uid)
            status, fetched = imap.uid("FETCH", str(uid), "(RFC822)")
            if status != "OK" or not fetched or not isinstance(fetched[0], tuple):
                log.warning("project=%s uid=%s fetch empty", account.project_id, uid)
                continue
            msg = email.message_from_bytes(fetched[0][1])
            if sender_address(msg) != expected:
                continue
            for item in items_from_message(msg, account.project_id, uid):
                if sink.seen(item):
                    continue
                try:
                    sink.commit(item)
                    committed += 1
                except Exception:
                    log.exception(
                        "project=%s uid=%s commit failed name=%s", account.project_id, uid, item.name
                    )
        config.set_imap_last_uid(account.project_id, newest)
        log.info("project=%s committed=%s newest_uid=%s", account.project_id, committed, newest)
        return committed
    finally:
        with contextlib.suppress(Exception):
            imap.logout()


def poll_once(sink: Sink, config: ConfigSource, **kwargs) -> int:
    """Poll every configured mailbox once. A failing mailbox is logged and does not stop the others."""
    total = 0
    for account in config.imap_accounts():
        try:
            total += poll_account(account, sink, config, **kwargs)
        except Exception:
            log.exception("project=%s imap poll failed", account.project_id)
    return total
