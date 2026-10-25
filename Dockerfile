# ==============================================================================
# Phonix v2.0 Enterprise Zero-Trust Gateway Dockerfile
# Multi-stage hardened build with non-root runtime user and strict egress gates
# ==============================================================================

# --- Stage 1: Build & Dependencies ---
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    fastapi>=0.115.0 \
    uvicorn[standard]>=0.30.0 \
    pydantic>=2.9.0 \
    z3-solver>=4.13.0 \
    httpx>=0.27.0 \
    pyyaml>=6.0.2 \
    pytest>=8.0.0

# --- Stage 2: Hardened Runtime Container ---
FROM python:3.11-slim AS runtime

LABEL maintainer="Phonix Enterprise Security <security@phonix.local>"
LABEL version="2.0.0"
LABEL description="Zero-Trust AST Paging & 1B Micro-Router Gateway"

WORKDIR /app

# Install runtime curl for healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python libraries from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Create zero-trust non-root service account
RUN groupadd -g 10001 phonix && \
    useradd -u 10001 -g phonix -m -s /bin/bash phonix

# Copy application source and configuration
COPY src/ /app/src/
COPY config/ /app/config/
COPY models/ /app/models/
COPY scripts/ /app/scripts/
COPY pyproject.toml /app/pyproject.toml

# Prepare writable data directory for SFT telemetry flywheel
RUN mkdir -p /app/data && chown -R phonix:phonix /app

USER phonix

EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PHONIX_WORKSPACE_ROOT=/app \
    PHONIX_OLLAMA_URL=http://phonix-ollama:11434 \
    PHONIX_OLLAMA_MODEL=qwen2.5-coder:1.5b

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/health || exit 1

ENTRYPOINT ["python", "-m", "src.main", "start", "--host", "0.0.0.0", "--port", "8000"]
