# Project: BRS-XSS v1.0.5 (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 13:22:00 MSK
# Status: Modified
# Telegram: https://t.me/EasyProTech

FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies for Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget gnupg ca-certificates \
    libglib2.0-0 libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 \
    libgbm1 libasound2 libxshmfence1 libpango-1.0-0 libpangocairo-1.0-0 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY pyproject.toml setup.py ./
COPY brsxss/ brsxss/
COPY cli/ cli/
COPY config/ config/

# Install application
RUN pip install --no-deps .

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
    CMD brs-xss version || exit 1

# Labels for better container management
LABEL org.opencontainers.image.title="BRS-XSS" \
      org.opencontainers.image.description="Context-aware async XSS scanner for CI" \
    org.opencontainers.image.version="1.0.5" \
      org.opencontainers.image.vendor="EasyProTech LLC" \
      org.opencontainers.image.source="https://github.com/EPTLLC/brs-xss" \
    org.opencontainers.image.licenses="GPL-3.0-or-later OR LicenseRef-Commercial"