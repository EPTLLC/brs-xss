#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

HTML Attribute Context - Description
"""

TITLE = "Cross-Site Scripting (XSS) in HTML Attribute"

DESCRIPTION = """
User input is reflected inside an HTML tag's attribute without proper escaping. This is one of the most 
common XSS vectors in modern web applications. Attackers can break out of the attribute context to inject 
event handlers, create new attributes, or even close the tag entirely to inject arbitrary HTML.

VULNERABILITY CONTEXT:
HTML attributes can contain user data in various contexts:
- value="USER_INPUT" in form fields
- href="USER_INPUT" in links
- src="USER_INPUT" in images/scripts
- alt="USER_INPUT" in images
- title="USER_INPUT" in tooltips
- data-*="USER_INPUT" in custom attributes
- style="USER_INPUT" in inline styles
- onclick="USER_INPUT" in event handlers
- class="USER_INPUT" in CSS classes
- id="USER_INPUT" in element IDs

Special risk exists with attributes that can execute JavaScript:
- href, src, action, formaction (URL attributes)
- All event handlers (onclick, onload, onerror, etc.)
- style (can contain expression() or url())
- srcdoc in iframes

SEVERITY: HIGH to CRITICAL
Depends on the specific attribute and quoting style. Unquoted attributes are most dangerous.
"""

