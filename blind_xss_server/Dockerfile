# Project: BRS-XSS Blind XSS Callback Server
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 25 Dec 2025 12:30:00 UTC

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi>=0.104.0 \
    uvicorn[standard]>=0.24.0 \
    pydantic>=2.5.0 \
    httpx>=0.25.0

# Copy server code
COPY . /app/blind_xss_server/

# Create directories
RUN mkdir -p /app/data /app/screenshots

# Environment
ENV PYTHONPATH=/app
ENV BLIND_XSS_DB=/app/data/blind_xss.db
ENV BLIND_XSS_SCREENSHOTS=/app/screenshots

EXPOSE 8888

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8888/health')" || exit 1

# Run server
CMD ["python", "-m", "uvicorn", "blind_xss_server.server:create_app", "--host", "0.0.0.0", "--port", "8888", "--factory"]

