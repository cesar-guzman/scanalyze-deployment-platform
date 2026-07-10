ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SCANALYZE_ENV=""
ENV SCANALYZE_TENANT=""
ENV SCANALYZE_PARAM_ROOT=""
ENV LOG_LEVEL="INFO"
ENV WORKER_MODE="INGEST"

WORKDIR /app

# Ensure current CA certificates and create an unprivileged runtime user.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && addgroup --system app \
    && adduser --system --ingroup app app \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app src/ ./src/

USER app

ENTRYPOINT ["python", "-m", "src.ocr_worker.main"]
