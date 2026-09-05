FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    TZ=UTC

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Vendor the UI assets into the image so the running container never needs a
# CDN. A host with restricted egress would otherwise serve an unstyled page.
# If the build itself has no network, the templates fall back to the CDN.
ARG BOOTSTRAP_VERSION=5.3.3
RUN mkdir -p static \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap@${BOOTSTRAP_VERSION}/dist/css/bootstrap.min.css" \
      -o static/bootstrap.min.css \
 && curl -fsSL "https://cdn.jsdelivr.net/npm/bootstrap@${BOOTSTRAP_VERSION}/dist/js/bootstrap.bundle.min.js" \
      -o static/bootstrap.bundle.min.js \
 || echo "WARNING: could not vendor Bootstrap; the UI will load it from the CDN at runtime."

COPY app ./app
COPY templates ./templates
COPY static ./static

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
  CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
