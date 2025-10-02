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
      run: pip install brs-xss
      
    - name: Run XSS Scan
      run: |
        brs-xss scan ${{ github.event.repository.html_url }} \
          -o xss-results.sarif \
          --format sarif \
          --safe-mode
          
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: xss-results.sarif
```

## GitLab CI

```yaml
xss_scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install brs-xss
    - brs-xss scan $CI_PROJECT_URL -o xss-results.json --safe-mode
  artifacts:
    reports:
      sast: xss-results.json
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
                sh 'brs-xss scan ${env.BUILD_URL} -o xss-results.sarif --safe-mode'
                publishSecurityReport sarif: 'xss-results.sarif'
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
      scan https://example.com -o /workspace/results.sarif
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
brs-xss scan url --timeout 30 --max-time 300
```

### Parallel Scanning
For multiple targets:
```bash
# Scan multiple URLs in parallel
echo "https://app1.com" > targets.txt
echo "https://app2.com" >> targets.txt
brs-xss scan -f targets.txt --threads 10
```

### Failure Handling
Configure CI to handle scan results:
```yaml
- name: Run XSS Scan
  run: brs-xss scan url -o results.sarif
  continue-on-error: true  # Don't fail build on vulnerabilities

- name: Check Results
  run: |
    if [ -f results.sarif ]; then
      VULNS=$(jq '.runs[0].results | length' results.sarif)
      if [ "$VULNS" -gt 0 ]; then
        echo "Found $VULNS vulnerabilities"
        exit 1
      fi
    fi
```
