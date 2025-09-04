# Project: BRS-XSS v2.0.0 (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 09:03:08 MSK
# Status: Modified
# Telegram: https://t.me/EasyProTech

# Multi-stage build for optimized image size
FROM python:3.11-slim-bookworm as builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy requirements and code for installation
COPY requirements/ requirements/
COPY pyproject.toml setup.py ./
COPY brsxss/ brsxss/
COPY cli/ cli/
COPY config/ config/

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install --user .

# Runtime stage
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:$PATH"

# Install system dependencies for Playwright (minimal set)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget gnupg ca-certificates \
    libglib2.0-0 libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 \
    libgbm1 libasound2 libxshmfence1 libpango-1.0-0 libpangocairo-1.0-0 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY brsxss/ brsxss/
COPY cli/ cli/
COPY config/ config/
COPY pyproject.toml setup.py ./

# Install application 
RUN pip install .

# Install browsers for Playwright (only Chromium for smaller image)
RUN playwright install chromium --with-deps

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash brsxss && \
    chown -R brsxss:brsxss /app
USER brsxss

# Create output directory
RUN mkdir -p /app/results

VOLUME ["/app/results"]

ENTRYPOINT ["brs-xss"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD brs-xss --version || exit 1

# Labels for better container management
LABEL org.opencontainers.image.title="BRS-XSS" \
      org.opencontainers.image.description="Context-aware async XSS scanner for CI" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.vendor="EasyProTech LLC" \
      org.opencontainers.image.source="https://github.com/EPTLLC/brs-xss" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"