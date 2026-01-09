# CI/CD Integration Guide

**Integrate BRS-XSS into your CI/CD pipeline**

## GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  xss-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Install BRS-XSS
      run: |
        pip install brs-xss
        playwright install chromium
        
    - name: Run XSS Scan
      run: |
        brs-xss scan ${{ github.event.repository.html_url }} \
          --output xss-results.json \
          --safe-mode
          
    - name: Upload Results
      uses: actions/upload-artifact@v4
      with:
        name: xss-results
        path: xss-results.json
```

## GitLab CI

```yaml
xss_scan:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install brs-xss
    - playwright install chromium
  script:
    - brs-xss scan $CI_PROJECT_URL --output xss-results.json --safe-mode
  artifacts:
    paths:
      - xss-results.json
    expire_in: 1 week
```

## Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('XSS Scan') {
            steps {
                sh 'pip install brs-xss'
                sh 'playwright install chromium'
                sh 'brs-xss scan ${env.BUILD_URL} --output xss-results.json --safe-mode'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'xss-results.json', allowEmptyArchive: true
                }
            }
        }
    }
}
```

## Docker in CI

```yaml
- name: XSS Scan with Docker
  run: |
    docker run --rm -v $(pwd):/workspace \
      ghcr.io/eptllc/brs-xss:latest \
      scan https://example.com --output /workspace/results.json
```

## Best Practices

### Safe Mode for CI
Always use `--safe-mode` in CI environments:
- Respects robots.txt
- Uses conservative rate limiting
- Enables URL denylist
- Limits crawl depth to 3

### Timeout Configuration
Set appropriate timeouts for CI:
```bash
brs-xss scan https://example.com --timeout 30
```

### Thread Control
Control concurrency for CI resources:
```bash
brs-xss scan https://example.com --threads 5 --max-payloads 200
```

### Failure Handling
Configure CI to handle scan results:
```yaml
- name: Run XSS Scan
  run: brs-xss scan https://example.com --output results.json
  continue-on-error: true  # Don't fail build on vulnerabilities

- name: Check Results
  run: |
    if [ -f results.json ]; then
      VULNS=$(jq '.vulnerabilities | length' results.json 2>/dev/null || echo "0")
      if [ "$VULNS" -gt 0 ]; then
        echo "Found $VULNS vulnerabilities"
        exit 1
      fi
    fi
```

## CLI Options for CI

| Option | Description | Recommended for CI |
|--------|-------------|-------------------|
| `--safe-mode` | Restrict dangerous payloads | Yes (default) |
| `--threads` | Max concurrent requests | 5-10 |
| `--timeout` | Request timeout (seconds) | 30 |
| `--max-payloads` | Max payloads per entry point | 100-200 |
| `--output` | Path to save JSON report | Required |
