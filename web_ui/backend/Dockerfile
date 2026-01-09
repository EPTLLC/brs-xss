# Project: BRS-XSS Web UI Backend
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 25 Dec 2025 14:00:00 UTC

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-up \
    fastapi>=0.104.0 \
    uvicorn[standard]>=0.24.0 \
    pydantic>=2.5.0 \
    httpx>=0.25.0 \
    websockets>=12.0

# Copy backend code
COPY . /app/web_ui/backend/

# Create data directory
RUN mkdir -p /app/data

# Environment
ENV PYTHONPATH=/app
ENV DATABASE_PATH=/app/data/brsxss_ui.db

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/api/health')" || exit 1

# Run server
CMD ["python", "-m", "uvicorn", "web_ui.backend.app:app", "--host", "0.0.0.0", "--port", "8000"]

