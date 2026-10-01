FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    KERNELASSESS_DATA=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY kernelassess ./kernelassess
RUN pip install ".[web]"

RUN useradd --system --uid 10001 --create-home app \
 && mkdir -p /data \
 && chown app:app /data
USER app
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"

ENTRYPOINT ["kernelassess"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080"]
