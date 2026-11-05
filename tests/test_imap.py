from email.message import EmailMessage

import pytest

from sparrow_comm.channels import imap

ADDR = "camera@example.org"


def make_msg(sender=f"Trail Cam <{ADDR}>", subject="Photo from CAM01", attachments=(("a.jpg", b"img-a"),)):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = ADDR
    m["Subject"] = subject
    m.set_content("body")
    for name, data in attachments:
        maintype, subtype = (
            ("image", "jpeg") if name.lower().endswith((".jpg", ".jpeg")) else ("application", "octet-stream")
        )
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return m.as_bytes()


class FakeImap:
    """Minimal IMAP4 stand-in that mimics the "n:*" quirk (always returns the newest UID)."""

    instances: list["FakeImap"] = []

    def __init__(self, mailbox: dict[int, bytes], password="pw"):
        self.mailbox = mailbox
        self.password = password
        self.logged_out = False
        self.searches = []

    def __call__(self, host, port):
        FakeImap.instances.append(self)
        return self

    def login(self, user, password):
        if password != self.password:
            raise RuntimeError("auth failed")

    def select(self, folder, readonly=False):
        return "OK", [b"1"]

    def uid(self, cmd, *args):
        if cmd == "SEARCH":
            criteria = args[1]
            self.searches.append(criteria)
            uids = sorted(self.mailbox)
            if criteria != "ALL":
                lo = int(criteria.split()[1].split(":")[0])
                uids = [u for u in uids if u >= lo] or uids[-1:]
            return "OK", [" ".join(map(str, uids)).encode()]
        if cmd == "FETCH":
            uid = int(args[0])
            return "OK", [(f"{uid} (RFC822)".encode(), self.mailbox[uid]), b")"]
        raise AssertionError(cmd)

    def logout(self):
        self.logged_out = True


@pytest.fixture
def account(store):
    store.set_imap_account(9, ADDR, "pw")
    [acct] = store.imap_accounts()
    assert acct.password == "pw"
    return acct


def test_poll_commits_and_advances_cursor(store, account):
    fake = FakeImap(
        {
            1: make_msg(),
            2: make_msg(sender="stranger@evil.test"),
            3: make_msg(subject="no camera here", attachments=(("b.JPG", b"img-b"), ("notes.txt", b"t"))),
        }
    )
    assert imap.poll_once(store, store, imap_factory=fake) == 2
    rows = store.items(9)
    assert sorted((r["name"], r["camera_name"]) for r in rows) == [("a.jpg", "CAM01"), ("b.JPG", "Trail Cam")]
    assert store.imap_accounts()[0].last_uid == 3
    assert fake.logged_out

    # Second poll: "4:*" returns UID 3 again (server quirk) and nothing is re-committed.
    assert imap.poll_once(store, store, imap_factory=fake) == 0
    assert fake.searches[-1] == "(UID 4:*)"
    fake.mailbox[4] = make_msg(attachments=(("a.jpg", b"img-a"),))  # duplicate bytes
    fake.mailbox[5] = make_msg(attachments=(("c.png", b"img-c"),))
    assert imap.poll_once(store, store, imap_factory=fake) == 1
    assert store.imap_accounts()[0].last_uid == 5


def test_commit_failure_is_skipped(store, account, monkeypatch):
    fake = FakeImap({1: make_msg(attachments=(("a.jpg", b"1"), ("b.jpg", b"2")))})
    real = store.commit

    def flaky(item):
        if item.name == "a.jpg":
            raise RuntimeError("disk full")
        return real(item)

    monkeypatch.setattr(store, "commit", flaky)
    assert imap.poll_account(account, store, store, imap_factory=fake) == 1
    assert [r["name"] for r in store.items()] == ["b.jpg"]


def test_one_failing_account_does_not_stop_others(store):
    store.set_imap_account(1, "a@x.org", "wrong")
    store.set_imap_account(2, ADDR, "pw")
    fake = FakeImap({1: make_msg()})
    assert imap.poll_once(store, store, imap_factory=fake) == 1
    assert store.items(2) and not store.items(1)


@pytest.mark.parametrize(
    ("sender", "subject", "expected"),
    [
        (ADDR, "Image from: Ridge_2", "Ridge_2"),
        (f"Ridge Cam <{ADDR}>", "Hello", "Ridge Cam"),
        (ADDR, "", "Unknown"),
        (ADDR, "=?utf-8?q?Photo_from_CAM9?=", "CAM9"),
    ],
)
def test_camera_name(sender, subject, expected):
    import email

    msg = email.message_from_bytes(make_msg(sender=sender, subject=subject))
    assert imap.camera_name_for(msg) == expected


def test_items_from_message_sanitises_names():
    import email

    msg = email.message_from_bytes(make_msg(attachments=(("../../evil name.jpg", b"x"),)))
    [item] = imap.items_from_message(msg, 1, 42)
    assert "/" not in item.name and item.name.endswith(".jpg")
    assert item.extra == {"msg_uid": 42, "subject": "Photo from CAM01"}
