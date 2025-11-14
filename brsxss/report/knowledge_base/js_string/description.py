#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript String Context - Description
"""

TITLE = "Cross-Site Scripting (XSS) in JavaScript String"

DESCRIPTION = """
User input is placed inside a JavaScript string literal without proper escaping. This is EXTREMELY 
common in legacy applications and server-side rendering. Attackers can break out of the string context 
to execute arbitrary code. The complexity increases with ES6 template literals, regex patterns, and 
multi-line strings.

VULNERABILITY CONTEXT:
Occurs when server-side code embeds user data inside JavaScript strings:
- <script>var name = 'USER_INPUT';</script>
- <script>var msg = "USER_INPUT";</script>
- <script>var template = `USER_INPUT`;</script> (ES6)
- <script>var pattern = /USER_INPUT/;</script>
- onclick="alert('USER_INPUT')"
- href="javascript:doSomething('USER_INPUT')"
- Inline event handlers with strings
- JSON strings embedded in JavaScript
- JSONP responses with string data
- Dynamic SQL/template queries in JavaScript

Common in:
- Server-side templates (EJS, Handlebars, Jinja2)
- Legacy PHP/ASP/JSP with inline JavaScript
- Analytics tracking codes
- Configuration objects
- Internationalization (i18n) strings
- Error messages
- User notifications

SEVERITY: CRITICAL
String context XSS allows full JavaScript execution and is one of the most common XSS vectors.
"""

