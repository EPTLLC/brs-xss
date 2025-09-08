# Safe Mode Guide

**Production-safe scanning guidelines**

## What is Safe Mode?

Safe mode enables conservative scanning suitable for production environments:

- **Rate Limited**: 8 RPS maximum
- **Respects robots.txt**: Honors crawling restrictions  
- **URL Denylist**: Avoids dangerous endpoints
- **Limited Depth**: Crawls maximum 3 levels deep
- **Timeout Protection**: 15-second request timeout
- **Sanitized Logging**: Removes sensitive data from logs

## Enabling Safe Mode

### Command Line
```bash
# Enable safe mode
brs-xss scan https://example.com --safe-mode

# Safe mode is enabled by default in v1.0.5.1
brs-xss scan https://example.com
```

### Configuration File
```toml
[scanner]
safe_mode = true
rate_limit = 8.0
timeout = 15
max_depth = 3
respect_robots = true
enable_denylist = true
```

### Environment Variable
```bash
export BRS_XSS_SAFE_MODE=true
brs-xss scan https://example.com
```

## Safe Mode Settings

### Rate Limiting
```bash
# Custom rate limit (requests per second)
brs-xss scan url --rate-limit 5.0

# Very conservative scanning
brs-xss scan url --rate-limit 1.0 --delay 2.0
```

### Concurrency Control
```bash
# Limit concurrent connections
brs-xss scan url --concurrency 8

# Single-threaded scanning
brs-xss scan url --concurrency 1
```

### Timeout Configuration
```bash
# Conservative timeouts
brs-xss scan url --timeout 30 --max-time 600
```

## URL Denylist

Configure URLs to avoid:

```toml
[security]
denylist_domains = [
    "admin.example.com",
    "internal.company.com"
]

denylist_patterns = [
    "*/admin/*",
    "*/logout*",
    "*/delete*",
    "*/api/v*/users/*/delete"
]
```

### Built-in Denylist
Safe mode automatically avoids:
- Admin panels (`/admin`, `/administrator`)
- Authentication endpoints (`/login`, `/logout`, `/auth`)
- Destructive actions (`/delete`, `/remove`, `/drop`)
- API write operations (`POST`, `PUT`, `DELETE` to `/api`)
- Database interfaces (`/phpmyadmin`, `/adminer`)

## Robots.txt Compliance

```bash
# Check robots.txt before scanning
curl https://example.com/robots.txt

# Safe mode automatically respects:
# - Disallow directives
# - Crawl-delay settings
# - User-agent restrictions
```

## Production Scanning Checklist

### Before Scanning
- [ ] Get written authorization
- [ ] Enable safe mode
- [ ] Configure appropriate rate limits
- [ ] Set up URL denylist
- [ ] Test on staging environment first
- [ ] Notify operations team

### During Scanning
- [ ] Monitor server resources
- [ ] Watch for error rate increases
- [ ] Check application logs
- [ ] Be ready to stop scan if issues occur

### After Scanning
- [ ] Review results for false positives
- [ ] Validate findings manually
- [ ] Document legitimate vulnerabilities
- [ ] Follow responsible disclosure

## Example Production Scan

```bash
#!/bin/bash
# production-scan.sh

# Set conservative limits
export BRS_XSS_SAFE_MODE=true
export BRS_XSS_RATE_LIMIT=2.0
export BRS_XSS_CONCURRENCY=4
export BRS_XSS_TIMEOUT=30

# Create results directory
mkdir -p ./scan-results/$(date +%Y-%m-%d)

# Run scan with full logging
brs-xss scan https://production-app.com \
  --safe-mode \
  --rate-limit 2.0 \
  --concurrency 4 \
  --timeout 30 \
  --max-depth 2 \
  -o "./scan-results/$(date +%Y-%m-%d)/prod-scan.sarif" \
  --format sarif \
  --verbose \
  2>&1 | tee "./scan-results/$(date +%Y-%m-%d)/scan.log"

echo "Scan completed. Results in ./scan-results/$(date +%Y-%m-%d)/"
```

## Monitoring and Alerting

### Log Analysis
```bash
# Monitor scan progress
tail -f scan.log | grep -E "(ERROR|WARNING|Found vulnerability)"

# Check for rate limiting
grep "rate limit" scan.log

# Verify safe mode is active
grep "Safe mode enabled" scan.log
```

### Server Monitoring
Monitor these metrics during scans:
- CPU usage
- Memory consumption  
- Network connections
- Response times
- Error rates

### Emergency Stop
```bash
# Find and stop BRS-XSS process
pkill -f "brs-xss"

# Or use Docker
docker stop $(docker ps -q --filter ancestor=ghcr.io/eptllc/brs-xss)
```

## Legal and Ethical Considerations

### Authorization Required
- Written permission from system owner
- Scope clearly defined
- Time window specified
- Emergency contacts provided

### Responsible Disclosure
- Report vulnerabilities privately first
- Allow reasonable time for fixes
- Follow coordinated disclosure timeline
- Don't exploit findings

### Documentation
- Keep detailed scan logs
- Document methodology
- Record all findings
- Maintain evidence chain
