# =============================================================================
# Backend Dockerfile — AI Threat Hunting & Incident Response Platform
# Two-stage build: builder (compiles wheels) → runtime (lean final image)
# =============================================================================

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1001 -s /bin/bash appuser

WORKDIR /app

COPY --from=builder /install /usr/local

# Copy entire project — all backend.* imports resolve from /app
COPY --chown=appuser:appuser . .

RUN mkdir -p /app/data/models /app/data/logs \
    && chown -R appuser:appuser /app/data

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -sf http://localhost:8000/ || exit 1

CMD ["sh", "-c", \
     "uvicorn backend.api.main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --workers ${WORKERS:-2} \
        --timeout-keep-alive 30 \
        --access-log"]
