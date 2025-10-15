# GitHub SARIF Integration

**Upload scan results to GitHub Security tab**

## Automatic Upload

Use the `upload-sarif` action in your workflow:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
      
    steps:
    - uses: actions/checkout@v4
    
    - name: Run BRS-XSS
      run: |
        pip install brs-xss
        brs-xss scan ${{ github.event.repository.html_url }} \
          -o brs-xss.sarif \
          --format sarif
          
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: brs-xss.sarif
        category: brs-xss-scan
```

## Manual Upload

Upload SARIF files using GitHub CLI:

```bash
# Generate SARIF report
brs-xss scan https://example.com -o report.sarif

# Upload to GitHub
gh api repos/:owner/:repo/code-scanning/sarifs \
  -f sarif=@report.sarif \
  -f ref=refs/heads/main \
  -f commit_sha=$(git rev-parse HEAD)
```

## SARIF Report Structure

BRS-XSS generates SARIF 2.1.0 compliant reports with:

- **Schema Compliance**: Validates against the official SARIF 2.1.0 schema.
- **Rich Diagnostics**: Includes vulnerability details, severity, CWE, and context.
- **Fingerprinting**: Uses stable identifiers for vulnerability tracking.
- **Version**: 2.0.1
- **Help URIs**: Provides links to detailed vulnerability explanations.

### Vulnerability Rules
- **XSS001**: Reflected XSS (High severity)
- **XSS002**: Stored XSS (Critical severity) 
- **XSS003**: DOM XSS (High severity)

### Result Properties
Each vulnerability includes:
- URL and parameter
- Payload used
- Context type (HTML, JavaScript, etc.)
- Confidence score
- Reproduction steps

## Viewing Results

After upload, view results in GitHub:

1. Go to repository **Security** tab
2. Click **Code scanning alerts**
3. Filter by tool: "BRS-XSS"
4. Click individual alerts for details

## Alert Management

### Dismissing False Positives
```yaml
- name: Dismiss False Positives
  run: |
    # Add logic to auto-dismiss known false positives
    gh api repos/:owner/:repo/code-scanning/alerts/ALERT_ID \
      -X PATCH \
      -f state=dismissed \
      -f dismissed_reason=false_positive
```

### Custom Filtering
Filter alerts by severity or context:
```bash
# Get only high-severity alerts
gh api repos/:owner/:repo/code-scanning/alerts \
  --jq '.[] | select(.rule.security_severity_level == "high")'
```

## Troubleshooting

### Permission Issues
Ensure workflow has required permissions:
```yaml
permissions:
  security-events: write
  contents: read
```

### SARIF Validation
Validate SARIF before upload:
```bash
# Install SARIF validator
npm install -g @microsoft/sarif-validator

# Validate report
sarif-validator report.sarif
```

### File Size Limits
GitHub SARIF limits:
- Max file size: 10MB
- Max results: 5000 per upload

For large scans, split results:
```bash
brs-xss scan large-site.com --max-results 1000 -o report.sarif
```
