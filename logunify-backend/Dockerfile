# syntax=docker/dockerfile:1.7
# LogUnify backend: hash-pinned dependencies, non-root, read-only-root-filesystem friendly (writes only under /data).
ARG PYTHON_IMAGE=python:3.13-slim-bookworm

FROM ${PYTHON_IMAGE} AS build
WORKDIR /build
COPY requirements.lock .
# --require-hashes: every wheel must match the hash recorded in requirements.lock (supply-chain integrity; works offline from a wheelhouse)
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.lock

FROM ${PYTHON_IMAGE}
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin logunify \
 && mkdir -p /data && chown 10001:10001 /data
COPY --from=build /opt/venv /opt/venv
# FORWARDER_ROOT: retention policy files, mounted read-only by compose (used by the compliance retention proof)
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 LOGUNIFY_AUTH_MODE=jwt \
    LOGUNIFY_ALERT_DB_PATH=/data/alerts.db LOGUNIFY_AUDIT_DB_PATH=/data/audit.db LOGUNIFY_STATE_DB_PATH=/data/state.db \
    LOGUNIFY_DLQ_PATH=/data/dlq.jsonl LOGUNIFY_RAW_ARCHIVE_DIR=/data/raw LOGUNIFY_COMPLIANCE_REPORT_DIR=/data/compliance \
    LOGUNIFY_ES_FORWARD_DLQ_PATH=/data/es-dlq.jsonl LOGUNIFY_FORWARDER_ROOT=/opt/forwarder
WORKDIR /app
COPY app ./app
COPY parser_fixtures ./parser_fixtures
USER 10001
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=4 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=3).status == 200 else 1)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
