# Full gateway image: all 3 detection layers, used by docker-compose.yml for the
# local end-to-end trilogy run. For the Render free tier use Dockerfile.render.
#
# Same hygiene as Dockerfile.render: base image pinned by digest, dependencies from a hash-locked
# file (requirements.lock, installed with --require-hashes), unprivileged runtime user, model
# integrity enforced. The build context is filtered by .dockerignore (virtual environments,
# red-team run output and scan reports do not belong in an image).
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# One package is upgraded past the digest-pinned base: Debian published libpcre2-8-0 10.46-1~deb13u3 (a fixed HIGH, CVE-2026-103111) before the
# python:3.12-slim image was rebuilt with it, and the Trivy image gate fails on a fixed HIGH. Drop this RUN when a refreshed base digest already has u3
# (the gate going green with it removed is the check). Everything else stays as pinned.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade libpcre2-8-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.lock .
RUN pip install --require-hashes --no-deps -r requirements.lock

COPY . .

RUN useradd --system --no-create-home --uid 10001 --shell /usr/sbin/nologin gateway \
    && mkdir -p /app/logs \
    && chown -R gateway:gateway /app/logs
USER gateway

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
# Full mode: torch classifier enabled.
ENV GATEWAY_LITE=0
ENV MODEL_INTEGRITY=enforce

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=3).raise_for_status()" || exit 1

CMD ["sh", "-c", "uvicorn gateway.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
