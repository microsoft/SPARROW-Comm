"""ASGI app that mounts the device and Reconyx routers on a :class:`~sparrow_comm.store.Store`."""

from __future__ import annotations

import os

from fastapi import FastAPI

from sparrow_comm import __version__
from sparrow_comm.device_api import make_device_router
from sparrow_comm.reconyx import make_reconyx_router
from sparrow_comm.store import Store


def create_app(store: Store, jwt_secret: str = "") -> FastAPI:
    app = FastAPI(title="sparrow-comm", version=__version__)
    app.include_router(make_device_router(store, store))
    app.include_router(make_reconyx_router(store, store, jwt_secret=jwt_secret))

    @app.get("/health")
    def health():
        return {"ok": True, "version": __version__}

    return app


def app_from_env() -> FastAPI:
    """Factory for ``uvicorn --factory sparrow_comm.app:app_from_env``."""
    store = Store(
        os.environ.get("SPARROW_COMM_DB", "sparrow-comm.db"),
        os.environ.get("SPARROW_COMM_DATA", "data"),
        os.environ.get("SPARROW_COMM_SECRET_KEY") or None,
    )
    return create_app(store, os.environ.get("SPARROW_COMM_JWT_SECRET", ""))
