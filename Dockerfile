FROM python:3.13-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv PATH=/opt/venv/bin:$PATH
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --extra all --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --extra all
ENV SPARROW_COMM_DB=/var/lib/sparrow-comm/sparrow-comm.db \
    SPARROW_COMM_DATA=/var/lib/sparrow-comm/data \
    FTPS_STAGING_DIR=/var/lib/sparrow-comm/staging
VOLUME /var/lib/sparrow-comm
ENTRYPOINT ["sparrow-comm"]
CMD ["serve", "api"]

# Simulator image for the local stack (docker/compose.yml); not for production.
FROM base AS sim
RUN uv pip install --python /opt/venv/bin/python httpx "psycopg[binary]"
COPY docker/selfsigned.py docker/simulate.py docker/parity.py /app/docker/
ENTRYPOINT ["python"]
