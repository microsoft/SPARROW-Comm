import datetime as dt
import ftplib
import io
import os
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sparrow_comm.channels import ftps


def age(path, seconds=60):
    t = time.time() - seconds
    os.utime(path, (t, t))


def stage(root, project, rel, data=b"img"):
    p = root / str(project) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    age(p)
    return p


@pytest.mark.parametrize(
    ("fname", "expected"),
    [
        ("Ridge_00_20260102030405.jpg", "Ridge"),
        ("ab12__Ridge-2_01_20260102030405.jpg", "Ridge-2"),
        ("CamA_20260102.jpg", "CamA"),
        ("photo from CAM7.jpg", "CAM7"),
        ("IMG_0001.JPG", "Unknown"),
    ],
)
def test_camera_name_from_filename(fname, expected):
    assert ftps.camera_name_from_filename(fname) == expected


def test_validate_credential(store):
    pw = store.set_ftps_password(4)
    assert ftps.validate_credential(store, "proj_4", pw)
    assert not ftps.validate_credential(store, "proj_4", "nope")
    assert not ftps.validate_credential(store, "proj_5", pw)
    assert not ftps.validate_credential(store, "proj_x", pw)
    assert not ftps.validate_credential(store, "admin", pw)
    assert store.set_ftps_password(4, "chosen") == "chosen"
    assert ftps.validate_credential(store, "proj_4", "chosen")


def test_poll_project(store, tmp_path):
    root = tmp_path / "staging"
    a = stage(root, 4, "Ridge_00_20260102030405.jpg", b"a")
    v = stage(root, 4, "sub/dir/clip.MP4", b"v")
    txt = stage(root, 4, "notes.txt")
    fresh = root / "4" / "fresh.jpg"
    fresh.write_bytes(b"f")
    assert ftps.poll_project(store, root, 4) == 2
    kinds = sorted((r["kind"], r["camera_name"]) for r in store.items(4))
    assert kinds == [("image", "Ridge"), ("video", "Unknown")]
    assert not a.exists() and not v.exists() and not (root / "4" / "sub").exists()
    assert txt.exists() and fresh.exists()


def test_poll_dedup_removes_source(store, tmp_path):
    root = tmp_path / "staging"
    stage(root, 4, "a.jpg", b"same")
    ftps.poll_project(store, root, 4)
    dup = stage(root, 4, "b.jpg", b"same")
    assert ftps.poll_project(store, root, 4) == 0
    assert not dup.exists()
    assert len(store.items()) == 1


def test_poll_commit_failure_keeps_source(store, tmp_path, monkeypatch):
    root = tmp_path / "staging"
    p = stage(root, 4, "a.jpg")

    def boom(item):
        raise RuntimeError("down")

    monkeypatch.setattr(store, "commit", boom)
    assert ftps.poll_project(store, root, 4) == 0
    assert p.exists()


def test_poll_oversize_dropped(store, tmp_path):
    root = tmp_path / "staging"
    p = stage(root, 4, "big.jpg", b"x" * 100)
    assert ftps.poll_project(store, root, 4, max_file_bytes=10) == 0
    assert not p.exists() and store.items() == []


def test_poll_once_uses_configured_projects(store, tmp_path):
    root = tmp_path / "staging"
    store.set_ftps_password(4)
    stage(root, 4, "a.jpg", b"1")
    stage(root, 5, "b.jpg", b"2")  # no credential for project 5
    assert ftps.poll_once(store, store, root) == 1


def test_resolve_masquerade_address():
    assert ftps.resolve_masquerade_address(None) is None
    assert ftps.resolve_masquerade_address("10.0.0.1") == "10.0.0.1"
    assert ftps.resolve_masquerade_address("localhost") in {"127.0.0.1", None}


def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return str(certfile), str(keyfile)


def test_make_server_requires_tls_files(store, tmp_path):
    with pytest.raises((FileNotFoundError, RuntimeError, ValueError)):
        ftps.make_server(store, tmp_path, str(tmp_path / "no.pem"), str(tmp_path / "no.key"))


def test_live_ftps_upload_then_poll(store, tmp_path):
    pytest.importorskip("pyftpdlib")
    certfile, keyfile = _self_signed(tmp_path)
    staging = tmp_path / "staging"
    pw = store.set_ftps_password(4)
    server = ftps.make_server(store, staging, certfile, keyfile, bind=("127.0.0.1", 0), passive_ports=None)
    port = server.address[1]
    t = threading.Thread(target=server.serve_forever, kwargs={"timeout": 0.1}, daemon=True)
    t.start()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Plain FTP (no AUTH TLS) must be refused before login.
        plain = ftplib.FTP()
        plain.connect("127.0.0.1", port, timeout=5)
        with pytest.raises(ftplib.error_perm):
            plain.login("proj_4", pw)
        plain.close()

        bad = ftplib.FTP_TLS(context=ctx)
        bad.connect("127.0.0.1", port, timeout=5)
        with pytest.raises(ftplib.error_perm):
            bad.login("proj_4", "wrong")
        bad.close()

        c = ftplib.FTP_TLS(context=ctx)
        c.connect("127.0.0.1", port, timeout=5)
        c.login("proj_4", pw)
        c.prot_p()
        c.mkd("2026")
        c.storbinary("STOR 2026/Ridge_00_20260102030405.jpg", io.BytesIO(b"live-bytes"))
        c.quit()
    finally:
        server.close_all()
        t.join(timeout=5)

    staged = staging / "4" / "2026" / "Ridge_00_20260102030405.jpg"
    assert staged.read_bytes() == b"live-bytes"
    age(staged)
    assert ftps.poll_once(store, store, staging) == 1
    [row] = store.items(4)
    assert (row["channel"], row["camera_name"]) == ("ftps", "Ridge")
