FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl libmagic1 libpcap-dev \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system aisoc \
    && adduser --system --ingroup aisoc aisoc

COPY pyproject.toml LICENSE README.md ./
# Stub packages so hatchling can resolve them during pip install;
# the real source is copied in the next COPY layer.
RUN mkdir -p core agents api \
    && touch core/__init__.py agents/__init__.py api/__init__.py \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[dev]"

COPY --chown=aisoc:aisoc . .

USER aisoc

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
