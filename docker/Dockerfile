FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr tesseract-ocr-eng libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -r hawkscan
WORKDIR /app

COPY hawk_scan/pyproject.toml hawk_scan/
COPY hawk_scan/hawk_scan/ hawk_scan/hawk_scan/
COPY hawk_scan/fingerprints/ hawk_scan/fingerprints/

RUN pip install --no-cache-dir ./hawk_scan[web]

ENV HAWKSCAN_FINGERPRINTS_DIR=/app/hawk_scan/fingerprints

USER hawkscan

EXPOSE 8000
CMD ["uvicorn", "hawk_scan.web.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
