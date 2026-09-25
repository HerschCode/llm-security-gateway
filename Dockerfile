# Full gateway image: all 3 detection layers, used by docker-compose.yml for the
# local end-to-end trilogy run. For the Render free tier use Dockerfile.render.
#
# Same hygiene as Dockerfile.render: base image pinned by digest, dependencies from a hash-locked
# file (requirements.lock, installed with --require-hashes), unprivileged runtime user, model
# integrity enforced. The build context is filtered by .dockerignore (virtual environments,
# red-team run output and scan reports do not belong in an image).
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

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
