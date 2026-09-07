# Full gateway image: all 3 detection layers, used by docker-compose.yml for the
# local end-to-end trilogy run. For the Render free tier use Dockerfile.render.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
# Full mode: torch classifier enabled.
ENV GATEWAY_LITE=0

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=3).raise_for_status()" || exit 1

CMD ["sh", "-c", "uvicorn gateway.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
