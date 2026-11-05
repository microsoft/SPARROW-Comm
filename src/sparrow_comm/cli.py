"""``sparrow-comm`` command line: manage credentials, run the API and FTPS servers, poll channels.

Settings come from flags or environment variables:

- ``SPARROW_COMM_DB`` (default ``sparrow-comm.db``), ``SPARROW_COMM_DATA`` (default ``data``)
- ``SPARROW_COMM_SECRET_KEY``: Fernet key for stored IMAP passwords (``sparrow-comm secret-key``)
- ``SPARROW_COMM_JWT_SECRET``: signs Reconyx session tokens; Reconyx answers 503 without it
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections.abc import Callable

from sparrow_comm.store import Store


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name) or default


def _store(args: argparse.Namespace) -> Store:
    return Store(args.db, args.data_dir, _env("SPARROW_COMM_SECRET_KEY"))


def _loop(fn: Callable[[], int], every: float | None) -> int:
    if not every:
        n = fn()
        print(n)
        return 0
    while True:
        try:
            fn()
        except Exception:
            logging.getLogger("sparrow_comm").exception("poll failed")
        time.sleep(every)


def _cmd_secret_key(args: argparse.Namespace) -> int:
    from cryptography.fernet import Fernet

    print(Fernet.generate_key().decode())
    return 0


def _cmd_keys_issue(args: argparse.Namespace) -> int:
    print(_store(args).issue_onboarding_key(args.project, args.email))
    return 0


def _cmd_device_settings(args: argparse.Namespace) -> int:
    _store(args).set_device_settings(args.device, json.loads(args.json))
    return 0


def _cmd_devices(args: argparse.Namespace) -> int:
    for d in _store(args).devices():
        print(json.dumps(d))
    return 0


def _cmd_ftps_password(args: argparse.Namespace) -> int:
    pw = _store(args).set_ftps_password(args.project, args.password)
    print(f"user=proj_{args.project} password={pw}")
    return 0


def _cmd_reconyx_key(args: argparse.Namespace) -> int:
    token = _store(args).issue_reconyx_key(args.project)
    print(f"id=proj_{args.project} token={token}")
    return 0


def _cmd_imap_add(args: argparse.Namespace) -> int:
    password = args.password or _env("SPARROW_COMM_IMAP_PASSWORD")
    if not password:
        print("error: --password or SPARROW_COMM_IMAP_PASSWORD is required", file=sys.stderr)
        return 2
    _store(args).set_imap_account(args.project, args.address, password)
    return 0


def _cmd_items(args: argparse.Namespace) -> int:
    for row in _store(args).items(args.project):
        print(json.dumps(row))
    return 0


def _cmd_serve_api(args: argparse.Namespace) -> int:
    import uvicorn

    from sparrow_comm.app import create_app

    app = create_app(_store(args), _env("SPARROW_COMM_JWT_SECRET", "") or "")
    uvicorn.run(app, host=args.host, port=args.port, proxy_headers=True)
    return 0


def _cmd_serve_ftps(args: argparse.Namespace) -> int:
    from sparrow_comm.channels.ftps import make_server

    lo, _, hi = args.passive_ports.partition("-")
    server = make_server(
        _store(args),
        args.staging,
        certfile=args.cert,
        keyfile=args.key,
        bind=(args.host, args.port),
        passive_ports=range(int(lo), int(hi or lo) + 1),
        masquerade_address=args.masquerade,
        tls_data_required=not args.no_tls_data,
    )
    server.serve_forever()
    return 0


def _cmd_poll_imap(args: argparse.Namespace) -> int:
    import imaplib

    from sparrow_comm.channels import imap

    store = _store(args)
    factory = imaplib.IMAP4 if args.no_ssl else imaplib.IMAP4_SSL
    return _loop(
        lambda: imap.poll_once(
            store, store, host=args.host, port=args.port, folder=args.folder, imap_factory=factory
        ),
        args.every,
    )


def _cmd_poll_ftps(args: argparse.Namespace) -> int:
    from sparrow_comm.channels import ftps

    store = _store(args)
    return _loop(lambda: ftps.poll_once(store, store, args.staging), args.every)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sparrow-comm", description=__doc__.splitlines()[0])
    p.add_argument("--db", default=_env("SPARROW_COMM_DB", "sparrow-comm.db"))
    p.add_argument("--data-dir", default=_env("SPARROW_COMM_DATA", "data"))
    p.add_argument("--log-level", default=_env("SPARROW_COMM_LOG_LEVEL", "INFO"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("secret-key", help="print a new Fernet key for SPARROW_COMM_SECRET_KEY")
    s.set_defaults(func=_cmd_secret_key)

    keys = sub.add_parser("keys", help="device onboarding keys").add_subparsers(dest="sub", required=True)
    s = keys.add_parser("issue", help="issue a one-time onboarding key")
    s.add_argument("--project", type=int, required=True)
    s.add_argument("--email", required=True, help="the device sends this as X-Email")
    s.set_defaults(func=_cmd_keys_issue)

    dev = sub.add_parser("devices", help="onboarded devices").add_subparsers(dest="sub", required=True)
    s = dev.add_parser("list")
    s.set_defaults(func=_cmd_devices)
    s = dev.add_parser("settings", help="set a device's settings (Studio column names, JSON)")
    s.add_argument("--device", type=int, required=True)
    s.add_argument("--json", required=True)
    s.set_defaults(func=_cmd_device_settings)

    ft = sub.add_parser("ftps", help="FTPS credentials").add_subparsers(dest="sub", required=True)
    s = ft.add_parser("set-password", help="set or generate the password for user proj_<project>")
    s.add_argument("--project", type=int, required=True)
    s.add_argument("--password")
    s.set_defaults(func=_cmd_ftps_password)

    rx = sub.add_parser("reconyx", help="Reconyx tokens").add_subparsers(dest="sub", required=True)
    s = rx.add_parser("issue-key", help="issue a token (deactivates earlier ones)")
    s.add_argument("--project", type=int, required=True)
    s.set_defaults(func=_cmd_reconyx_key)

    im = sub.add_parser("imap", help="IMAP mailboxes").add_subparsers(dest="sub", required=True)
    s = im.add_parser("add", help="add or replace a project's mailbox")
    s.add_argument("--project", type=int, required=True)
    s.add_argument("--address", required=True)
    s.add_argument("--password", help="app password (or SPARROW_COMM_IMAP_PASSWORD)")
    s.set_defaults(func=_cmd_imap_add)

    s = sub.add_parser("items", help="list received items as JSON lines")
    s.add_argument("--project", type=int)
    s.set_defaults(func=_cmd_items)

    serve = sub.add_parser("serve", help="run a server").add_subparsers(dest="sub", required=True)
    s = serve.add_parser("api", help="device API and Reconyx (needs the 'serve' extra)")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=_cmd_serve_api)
    s = serve.add_parser("ftps", help="FTPS server (needs the 'ftps' extra)")
    s.add_argument("--staging", default=_env("FTPS_STAGING_DIR", "staging/ftps"))
    s.add_argument("--cert", default=_env("CERT_FILE"), required=not _env("CERT_FILE"))
    s.add_argument("--key", default=_env("KEY_FILE"), required=not _env("KEY_FILE"))
    s.add_argument("--host", default=_env("FTPS_BIND_ADDR", "0.0.0.0"))
    s.add_argument("--port", type=int, default=int(_env("FTPS_PORT", "21") or 21))
    s.add_argument("--passive-ports", default=_env("FTPS_PASSIVE_PORTS", "51000-51050"))
    s.add_argument("--masquerade", default=_env("FTPS_MASQUERADE_ADDR"))
    s.add_argument("--no-tls-data", action="store_true", help="allow plaintext data channels")
    s.set_defaults(func=_cmd_serve_ftps)

    poll = sub.add_parser("poll", help="poll a pull channel").add_subparsers(dest="sub", required=True)
    s = poll.add_parser("imap")
    s.add_argument("--host", default=_env("IMAP_HOST", "imap.gmail.com"))
    s.add_argument("--port", type=int, default=int(_env("IMAP_PORT", "993") or 993))
    s.add_argument("--folder", default="INBOX")
    s.add_argument("--no-ssl", action="store_true", help="plain IMAP (local test servers only)")
    s.add_argument("--every", type=float, help="repeat every N seconds instead of once")
    s.set_defaults(func=_cmd_poll_imap)
    s = poll.add_parser("ftps")
    s.add_argument("--staging", default=_env("FTPS_STAGING_DIR", "staging/ftps"))
    s.add_argument("--every", type=float, help="repeat every N seconds instead of once")
    s.set_defaults(func=_cmd_poll_ftps)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
