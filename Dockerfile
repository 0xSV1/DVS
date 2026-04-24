# Damn Vulnerable Startup: multi-stage Docker build
# WARNING: This application is DELIBERATELY VULNERABLE. Do not expose to the internet.

# ── Build stage ─────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

# ── Test stage (not included in production image) ─────────────
FROM python:3.11-slim AS test

WORKDIR /app

COPY --from=builder /build/deps /usr/local/lib/python3.11/site-packages/
COPY app/ app/
COPY data/ data/
COPY tests/ tests/

ENV PYTHONUNBUFFERED=1 \
    LLM_PROVIDER=mock \
    DATABASE_URL=sqlite:// \
    SECRET_KEY=test-only \
    CTF_KEY=test-ctf-key

CMD ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]

# ── Runtime stage ───────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="DVS Contributors"
LABEL description="Damn Vulnerable Startup: deliberately vulnerable security training platform"

# Non-root user for the framework itself (vuln challenges run in-process)
RUN groupadd -r dvs && useradd -r -g dvs -d /app -s /sbin/nologin dvs

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /build/deps /usr/local/lib/python3.11/site-packages/

# Copy application code
COPY app/ app/
COPY data/ data/

# Ensure runtime and upload directories are writable for SQLite and challenges
RUN mkdir -p /app/data /app/runtime /app/uploads /app/app/static/uploads \
    && chown -R dvs:dvs /app/data /app/runtime /app/uploads /app/app/static/uploads

# Switch to non-root
USER dvs

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECRET_KEY=change-me-in-production \
    DATABASE_URL=sqlite:////app/runtime/dvs.db \
    CTF_MODE=false \
    CTF_KEY=default-ctf-key-change-me \
    LLM_PROVIDER=mock \
    DEFAULT_DIFFICULTY=intern \
    UNSAFE_CHALLENGES=false

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
