# Docker Usage Guide

**Run BRS-XSS in containers**

## Quick Start

```bash
# Pull latest image
docker pull ghcr.io/eptllc/brs-xss:latest

# Run scan
docker run --rm ghcr.io/eptllc/brs-xss:latest scan https://example.com
```

## Volume Mounting

Save results to host filesystem:

```bash
# Create results directory
mkdir -p ./results

# Run with volume mount
docker run --rm \
  -v $(pwd)/results:/app/results \
  ghcr.io/eptllc/brs-xss:latest \
  scan https://example.com -o /app/results/report.sarif
```

## Configuration

Mount custom configuration:

```bash
# Create config file
cat > config.toml << EOF
[scanner]
concurrency = 16
rate_limit = 4.0
timeout = 20

[payloads]
aggr_mode = true
EOF

# Run with custom config
docker run --rm \
  -v $(pwd)/config.toml:/app/config/user.toml \
  -v $(pwd)/results:/app/results \
  ghcr.io/eptllc/brs-xss:latest \
  scan https://example.com --config /app/config/user.toml
```

## Docker Compose

```yaml
version: '3.8'
services:
  brs-xss:
    image: ghcr.io/eptllc/brs-xss:latest
    volumes:
      - ./results:/app/results
      - ./config.toml:/app/config/user.toml
    command: scan https://example.com -o /app/results/report.sarif
    environment:
      - BRS_XSS_SAFE_MODE=true
      - BRS_XSS_LOG_LEVEL=INFO
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: XSS Scan with Docker
  run: |
    docker run --rm \
      -v ${{ github.workspace }}/results:/app/results \
      ghcr.io/eptllc/brs-xss:latest \
      scan ${{ github.event.repository.html_url }} \
      -o /app/results/xss.sarif \
      --safe-mode
```

### GitLab CI
```yaml
xss_scan:
  image: ghcr.io/eptllc/brs-xss:latest
  script:
    - brs-xss scan $CI_PROJECT_URL -o xss-results.sarif --safe-mode
  artifacts:
    reports:
      sast: xss-results.sarif
```

## Multi-Architecture Support

The image supports multiple architectures:
- linux/amd64 (Intel/AMD)
- linux/arm64 (Apple Silicon, ARM servers)

```bash
# Specific architecture
docker pull --platform linux/arm64 ghcr.io/eptllc/brs-xss:latest
```

## Environment Variables

Configure via environment variables:

```bash
docker run --rm \
  -e BRS_XSS_CONCURRENCY=20 \
  -e BRS_XSS_RATE_LIMIT=10.0 \
  -e BRS_XSS_TIMEOUT=30 \
  -e BRS_XSS_SAFE_MODE=true \
  ghcr.io/eptllc/brs-xss:latest \
  scan https://example.com
```

Available environment variables:
- `BRS_XSS_CONCURRENCY` - Concurrent requests
- `BRS_XSS_RATE_LIMIT` - Requests per second
- `BRS_XSS_TIMEOUT` - Request timeout
- `BRS_XSS_SAFE_MODE` - Enable safe mode
- `BRS_XSS_LOG_LEVEL` - Logging level

## Building Custom Images

```dockerfile
FROM ghcr.io/eptllc/brs-xss:latest

# Add custom payloads
COPY custom-payloads/ /app/custom-payloads/

# Add custom configuration
COPY custom-config.toml /app/config/custom.toml

# Set default config
ENV BRS_XSS_CONFIG=/app/config/custom.toml
```

## Troubleshooting

### Permission Issues
If running as non-root user:
```bash
docker run --rm \
  --user $(id -u):$(id -g) \
  -v $(pwd)/results:/app/results \
  ghcr.io/eptllc/brs-xss:latest \
  scan https://example.com
```

### Network Access
For internal targets, use host networking:
```bash
docker run --rm --network host \
  ghcr.io/eptllc/brs-xss:latest \
  scan http://localhost:8080
```

### Browser Issues
If DOM analysis fails, increase shared memory:
```bash
docker run --rm --shm-size=2g \
  ghcr.io/eptllc/brs-xss:latest \
  scan https://example.com --deep
```
