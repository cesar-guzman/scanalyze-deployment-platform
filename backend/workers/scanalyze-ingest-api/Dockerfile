ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=80

WORKDIR /app

# libcap2-bin para setcap. Capamos python para bindear a 80 sin root.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && addgroup --system app && adduser --system --ingroup app app \
    && PY_BIN="$(python -c 'import os, sys; print(os.path.realpath(sys.executable))')" \
    && setcap 'cap_net_bind_service=+ep' "$PY_BIN" \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app app ./app
COPY --chown=app:app gunicorn_conf.py ./

USER app

EXPOSE 80

CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-c", "gunicorn_conf.py", "app.main:app"]
