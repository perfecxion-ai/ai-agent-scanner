FROM python:3.12-slim AS base

LABEL maintainer="Scott Thornton <scthornton@gmail.com>"
LABEL description="AI Agent Scanner — Discover, assess, and secure AI agents"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash scanner
USER scanner

EXPOSE 5000

# Default: run the web application
CMD ["python", "app.py"]
