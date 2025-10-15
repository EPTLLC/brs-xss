#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: XML Content Context
"""

DETAILS = {
    "title": "Cross-Site Scripting (XSS) in XML Context",
    
    "description": """
User input is reflected within XML or XHTML documents without proper encoding. XML-based XSS can 
occur in RSS feeds, SOAP web services, SVG files, or XHTML pages. The attack surface includes XML 
attributes, CDATA sections, and entity references.

SEVERITY: MEDIUM to HIGH
Common in RSS feeds, SOAP APIs, and XHTML applications.
""",

    "attack_vector": """
BASIC XML INJECTION:
<item><title>USER_INPUT</title></item>
Payload: </title><script>alert(1)</script><title>

CDATA BREAKOUT:
<![CDATA[USER_INPUT]]>
Payload: ]]><script>alert(1)</script><![CDATA[

XML ENTITIES:
&lt;script&gt;alert(1)&lt;/script&gt;
May be decoded during processing

XHTML INJECTION:
<p>USER_INPUT</p>
Payload: <img src=x onerror="alert(1)"/>

SOAP INJECTION:
XML in SOAP messages can target both structure and embedded HTML

RSS FEED XSS:
<description>USER_INPUT</description>
""",

    "remediation": """
DEFENSE:

1. XML ENTITY ENCODING
   Encode: &, <, >, ", '
   To: &amp;, &lt;, &gt;, &quot;, &apos;

2. USE XML LIBRARIES
   Python: xml.etree.ElementTree, defusedxml
   PHP: DOMDocument, SimpleXML
   JavaScript: DOMParser

3. VALIDATE WITH XML SCHEMA
4. DISABLE EXTERNAL ENTITIES (prevent XXE)
5. Apply HTML encoding for XHTML
6. Use Content-Type: application/xml
7. Implement CSP headers
8. Validate SVG uploads

Python:
from defusedxml import ElementTree as ET
tree = ET.fromstring(xml_content)

PHP:
libxml_disable_entity_loader(true);

OWASP REFERENCES:
- CWE-79: Cross-site Scripting
- CWE-611: XXE
- OWASP XML Security Cheat Sheet
"""
}
