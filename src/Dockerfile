# ============================================================================
# COMPLIANCE ARCHITECTURE - Unified Dockerfile
# ============================================================================
# Build context: backend repo root (compose.yml directory).

FROM python:3.12-slim AS base

RUN mkdir -p /app && \
    useradd -u 1000 -m app && \
    useradd -u 1001 -m messaging && \
    useradd -u 1002 -m -s /bin/false filestorage

WORKDIR /app

COPY utils/healthcheck.py /usr/local/bin/healthcheck.py
RUN chmod +x /usr/local/bin/healthcheck.py

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

FROM base AS main

COPY src/main/ ./src/main/
COPY src/shared/ ./src/shared/
COPY alembic/ ./alembic/
COPY alembic.ini ./

RUN mkdir -p /app/data /app/logs /app/alembic/versions && \
    chown -R app:app /app/data /app/logs /app/alembic

USER app

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 /usr/local/bin/healthcheck.py

EXPOSE ${PORT:-8300}

CMD ["python", "-m", "src.main.main"]

FROM base AS messaging

COPY src/messaging/ ./src/messaging/
COPY src/shared/ ./src/shared/

RUN chown -R messaging:messaging /app && \
    chmod 700 /app

USER messaging

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 /usr/local/bin/healthcheck.py

EXPOSE ${PORT:-8301}

CMD ["python", "-m", "src.messaging.main"]

FROM base AS file_storage

COPY src/file_storage/ ./src/file_storage/
COPY src/shared/ ./src/shared/

RUN mkdir -p /app/files && \
    chown -R filestorage:filestorage /app && \
    chmod 700 /app

USER filestorage

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 /usr/local/bin/healthcheck.py

EXPOSE ${PORT:-8302}

CMD ["python", "-m", "src.file_storage.main"]

FROM base AS chat_filter

RUN useradd -u 1003 -m chatfilter

COPY src/chat_filter/ ./src/chat_filter/
COPY src/shared/ ./src/shared/

RUN mkdir -p /data && \
    chown -R chatfilter:chatfilter /app /data

USER chatfilter

ENV DATA_DIR=/data

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 /usr/local/bin/healthcheck.py

EXPOSE ${PORT:-8305}

CMD ["python", "-m", "src.chat_filter.main"]
