import json
from datetime import datetime

import pytest

from sparrow_comm import cli
from sparrow_comm.items import Item
from sparrow_comm.store import Store
from sparrow_comm.util import sha256_bytes


def item(data=b"abc", project=1, name="a.jpg", **kw):
    return Item(
        kind="image",
        channel="device",
        project_id=project,
        data=data,
        sha256=sha256_bytes(data),
        name=name,
        **kw,
    )


def test_commit_layout_and_dedup(store):
    it = item(captured_at=datetime(2026, 1, 2, 3, 4, 5))
    assert not store.seen(it)
    first = store.commit(it)
    assert store.seen(it)
    assert store.commit(item(name="other.jpg")).id == first.id
    assert store.commit(item(project=2)).id != first.id
    [row] = store.items(1)
    assert row["path"].startswith("1/image/")
    assert row["path"].endswith(f"{it.sha256[:16]}__a.jpg")
    assert (store.data_dir / row["path"]).read_bytes() == b"abc"


def test_onboarding_key_consumed_once(store):
    raw = store.issue_onboarding_key(1, "A@B.org")
    from sparrow_comm.util import sha256_hex

    key = store.onboarding_key_by_hash(sha256_hex(raw))
    assert key.created_by_email == "a@b.org"
    did = store.consume_onboarding_key(key, "u1")
    assert store.consume_onboarding_key(store.onboarding_key_by_hash(sha256_hex(raw)), "u1") == did
    assert store.device_by_key_hash(sha256_hex(raw)).unit_id == "u1"


def test_imap_requires_secret_key(tmp_path):
    s = Store(tmp_path / "db", tmp_path / "d")
    with pytest.raises(RuntimeError):
        s.set_imap_account(1, "a@b", "pw")


def run(capsys, tmp_path, *argv):
    rc = cli.main(["--db", str(tmp_path / "cli.db"), "--data-dir", str(tmp_path / "d"), *argv])
    return rc, capsys.readouterr().out.strip()


def test_cli_admin_flow(capsys, tmp_path, monkeypatch):
    rc, key = run(capsys, tmp_path, "secret-key")
    assert rc == 0 and len(key) == 44
    monkeypatch.setenv("SPARROW_COMM_SECRET_KEY", key)

    rc, onboarding = run(capsys, tmp_path, "keys", "issue", "--project", "3", "--email", "x@y.org")
    assert rc == 0 and len(onboarding) > 20
    rc, out = run(capsys, tmp_path, "ftps", "set-password", "--project", "3", "--password", "pw")
    assert out == "user=proj_3 password=pw"
    rc, out = run(capsys, tmp_path, "reconyx", "issue-key", "--project", "3")
    assert out.startswith("id=proj_3 token=")
    rc, _ = run(capsys, tmp_path, "imap", "add", "--project", "3", "--address", "c@y.org", "--password", "pw")
    assert rc == 0
    monkeypatch.delenv("SPARROW_COMM_IMAP_PASSWORD", raising=False)
    rc, _ = run(capsys, tmp_path, "imap", "add", "--project", "3", "--address", "c@y.org")
    assert rc == 2

    store = Store(tmp_path / "cli.db", tmp_path / "d", key)
    assert store.imap_accounts()[0].address == "c@y.org"
    store.commit(item(project=3))
    rc, out = run(capsys, tmp_path, "items", "--project", "3")
    assert json.loads(out)["name"] == "a.jpg"


def test_cli_poll_ftps_once(capsys, tmp_path):
    staging = tmp_path / "staging"
    run(capsys, tmp_path, "ftps", "set-password", "--project", "3")
    f = staging / "3" / "a.jpg"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"x")
    import os

    os.utime(f, (0, 0))
    rc, out = run(capsys, tmp_path, "poll", "ftps", "--staging", str(staging))
    assert (rc, out) == (0, "1")
