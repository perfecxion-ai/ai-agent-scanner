FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE scanner_cli.py ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[server]"

FROM python:3.12-slim

LABEL maintainer="perfecXion.ai"
LABEL description="AI Agent Scanner - Discover, assess, and secure AI agents"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels "ai-agent-scanner[server]" \
    && rm -rf /wheels \
    && useradd --create-home --shell /usr/sbin/nologin scanner \
    && mkdir -m 0700 /app/instance \
    && chown scanner:scanner /app/instance
COPY app.py ./
COPY gunicorn.conf.py ./
COPY templates ./templates
COPY static ./static
COPY scripts/container-entrypoint.sh ./
USER scanner
EXPOSE 5000
ENTRYPOINT ["sh", "/app/container-entrypoint.sh"]
# Startup recovery requires one dispatcher process per database.
CMD ["gunicorn", "--config", "gunicorn.conf.py", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
