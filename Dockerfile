FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_BIND_HOST=0.0.0.0 \
    DATA_DIR=/data

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --gid app --home-dir /app app \
    && mkdir -p /data \
    && chown app:app /data

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py init.sql ./
COPY static ./static

USER app:app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]