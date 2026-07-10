import os

bind = f"0.0.0.0:{os.getenv('PORT', '8080')}"

# En Fargate suele ser mejor arrancar conservador y escalar horizontalmente.
workers = int(os.getenv("WEB_CONCURRENCY", "2"))

worker_class = "uvicorn.workers.UvicornWorker"

timeout = int(os.getenv("GUNICORN_TIMEOUT", "60"))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))

# Evitamos access logs no-JSON; la app hace request logging JSON.
accesslog = None
errorlog = "-"

loglevel = os.getenv("LOG_LEVEL", "info").lower()
