ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# The approved base must provide Python 3.11.14, CA certificates, pip, and the
# Debian adduser utilities. No package manager may reach the network here.
RUN python -c 'import sys; expected = (3, 11, 14); actual = sys.version_info[:3]; sys.exit(f"expected Python {expected!r}, got {actual!r}") if actual != expected else None' \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && addgroup --system app \
    && adduser --system --ingroup app app

COPY requirements.lock .
COPY .wheelhouse/ /wheelhouse/
RUN python -m pip install \
        --no-cache-dir \
        --no-index \
        --find-links=/wheelhouse \
        --require-hashes \
        -r requirements.lock \
    && rm -rf /wheelhouse

COPY --chown=app:app src/ ./src/

USER app

ENTRYPOINT ["python", "-m", "classifier_worker.main"]
