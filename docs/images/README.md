# Screenshots

Place the following screenshots here for README.md:

## Required Screenshots

### 1. dashboard.png
- URL: http://178.72.133.95:5174/
- Content: Main dashboard with stats, recent scans
- Size: ~1200x800 recommended

### 2. new-scan.png  
- URL: http://178.72.133.95:5174/scan/new
- Content: New scan form with BRS-KB stats banner
- Size: ~1200x800 recommended

### 3. scan-details.png
- URL: http://178.72.133.95:5174/scan/{scan_id} (after running a scan)
- Content: Scan results with vulnerabilities, terminal output
- Size: ~1200x800 recommended

## How to Take Screenshots

### Option 1: Browser
1. Open URL in browser
2. Use browser dev tools (F12) > Device toolbar > Set resolution
3. Right-click > Take screenshot

### Option 2: macOS
```bash
# Full screen
screencapture -x dashboard.png

# Selected area
screencapture -i dashboard.png
```

### Option 3: Linux (scrot)
```bash
scrot -d 3 dashboard.png  # 3 second delay
```

### Option 4: Playwright (automated)
```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={'width': 1200, 'height': 800})
    
    # Dashboard
    page.goto('http://178.72.133.95:5174/')
    page.wait_for_timeout(2000)
    page.screenshot(path='dashboard.png')
    
    # New Scan
    page.goto('http://178.72.133.95:5174/scan/new')
    page.wait_for_timeout(2000)
    page.screenshot(path='new-scan.png')
    
    browser.close()
```

## Image Guidelines

- Format: PNG (preferred) or JPG
- Max file size: 500KB each
- Resolution: 1200x800 or similar
- Theme: Dark theme looks best

