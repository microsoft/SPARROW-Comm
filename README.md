# sparrow-comm

Receivers for SPARROW field data. `sparrow-comm` accepts camera-trap images, audio and device
telemetry over four channels and hands each received file to your storage code:

| Channel | How data arrives | Entry point |
|---|---|---|
| Device API | SPARROW field units push over HTTPS (`/v1/onboarding`, `/v1/uploads/*`, `/v1/metrics/*`, `/v1/settings/*`) | `make_device_router` |
| Reconyx | Reconyx cloud forwards base64 images (`/v1/reconyx/login`, `/v1/reconyx/images`) | `make_reconyx_router` |
| E-mail | Cellular cameras e-mail photos to a mailbox; the poller reads it over IMAP | `channels.imap.poll_once` |
| FTPS | Cameras upload over explicit FTP-over-TLS; the poller ingests finished files | `channels.ftps.make_server`, `channels.ftps.poll_once` |

The request and response formats match Sparrow Studio's receivers, so field devices and cameras
configured for Studio work unchanged.

GPS tracking and device firmware delivery are not part of this release.

## Install

```bash
pip install "sparrow-comm[all]"     # everything
pip install sparrow-comm            # device API, Reconyx and IMAP only
pip install "sparrow-comm[ftps]"    # adds the FTPS server (pyftpdlib, pyOpenSSL)
pip install "sparrow-comm[serve]"   # adds uvicorn for `sparrow-comm serve api`
```

Python 3.12 or newer.

## Run it standalone

The bundled SQLite `Store` keeps devices, keys and credentials in one database file and writes
received files under a data directory (`<data>/<project>/<kind>/<date>/<sha256 prefix>__<name>`).

```bash
export SPARROW_COMM_DB=./sparrow-comm.db SPARROW_COMM_DATA=./data
export SPARROW_COMM_SECRET_KEY=$(sparrow-comm secret-key)   # encrypts stored IMAP passwords
export SPARROW_COMM_JWT_SECRET=change-me                     # signs Reconyx tokens

sparrow-comm keys issue --project 1 --email you@example.org  # one-time device onboarding key
sparrow-comm reconyx issue-key --project 1                   # Reconyx id/token pair
sparrow-comm ftps set-password --project 1                   # FTPS user proj_1
sparrow-comm imap add --project 1 --address cam@example.org  # reads SPARROW_COMM_IMAP_PASSWORD

sparrow-comm serve api --port 8000
sparrow-comm serve ftps --cert cert.pem --key key.pem --port 21
sparrow-comm poll imap --every 60
sparrow-comm poll ftps --every 30

sparrow-comm items --project 1      # received items as JSON lines
```

Run `sparrow-comm <command> --help` for every option. Settings can also come from environment
variables: `SPARROW_COMM_DB`, `SPARROW_COMM_DATA`, `SPARROW_COMM_LOG_LEVEL`, `IMAP_HOST`,
`IMAP_PORT`, `FTPS_STAGING_DIR`, `FTPS_PORT`, `FTPS_BIND_ADDR`, `FTPS_PASSIVE_PORTS`,
`FTPS_MASQUERADE_ADDR`, `CERT_FILE`, `KEY_FILE`.

The FTPS server refuses plaintext logins and, unless `--no-tls-data` is given, plaintext data
connections. Each project logs in as `proj_<id>` and is confined to its own staging folder. The
poller ingests files that have not changed for 5 seconds and deletes each one only after it is
stored (or already present).

## Use it inside your own application

Every channel talks to storage through three small interfaces in `sparrow_comm.hooks`.
Implement them over your own database and pass your objects in; nothing else in the package
touches storage.

| Hook | Used by | Methods |
|---|---|---|
| `Sink` | all channels | `seen(item)`, `commit(item) -> CommitResult` |
| `DeviceRegistry` | device API | `device_by_key_hash`, `onboarding_key_by_hash`, `issuer_can_manage`, `consume_onboarding_key`, `device_settings`, `record_metrics` |
| `ConfigSource` | IMAP, FTPS, Reconyx | `imap_accounts`, `set_imap_last_uid`, `ftps_projects`, `ftps_credential`, `record_ftps_usage`, `reconyx_key`, `mark_reconyx_key_used`, `reconyx_key_authorized` |

Each received file reaches `Sink.commit` as an `Item`: kind (`image`, `video`, `audio`),
channel, project id, the bytes and their SHA-256, a safe file name, and whatever the channel
knows (device, camera name, capture time as naive UTC, detections, channel-specific `extra`).
`commit` should be idempotent on `(project_id, kind, sha256)` and return `CommitResult(id, created)`.
Raising `ValueError` from `commit` turns into an HTTP 400 with your message on the device API.

```python
from fastapi import FastAPI
from sparrow_comm.device_api import make_device_router
from sparrow_comm.reconyx import make_reconyx_router

app = FastAPI()
app.include_router(make_device_router(registry=my_registry, sink=my_sink))
app.include_router(make_reconyx_router(config=my_config, sink=my_sink, jwt_secret=SECRET))
```

```python
from sparrow_comm.channels import ftps, imap

imap.poll_once(my_sink, my_config, host="imap.gmail.com")
ftps.poll_once(my_sink, my_config, "/srv/staging/ftps")
```

`sparrow_comm.store.Store` implements all three hooks and is a working reference.

## Local test stack

`docker/compose.yml` runs the API, the FTPS server, both pollers and a GreenMail mail server.
The simulator acts as a device, a Reconyx forwarder, an FTPS camera and an e-mail camera, then
checks that each payload was stored exactly once.

```bash
docker compose -f docker/compose.yml up -d --build
docker compose -f docker/compose.yml --profile sim run --rm sim
docker compose -f docker/compose.yml down -v
```

The secrets in that file are fixed development values.

### Comparing with Sparrow Studio

With a Sparrow Studio checkout, `docker/parity.compose.yml` runs Studio's device and Reconyx
server next to sparrow-comm. `docker/parity.py` sends both the same 48 requests and compares
status codes and response bodies. Values generated per server, such as ids, tokens and
timestamps, are masked. The script exits 1 on any unexpected difference. It lists two inputs
on which Studio returns HTTP 500 as known Studio defects.

```bash
export STUDIO_DIR=/path/to/sparrow-studio
docker compose -f docker/parity.compose.yml up -d --build --wait
docker compose -f docker/parity.compose.yml --profile parity run --rm --build parity
docker compose -f docker/parity.compose.yml down -v
```

## Development

```bash
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit [Contributor License Agreements](https://cla.opensource.microsoft.com).

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
