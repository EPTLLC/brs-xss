#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript Context - Description
"""

TITLE = "Cross-Site Scripting (XSS) in JavaScript Context"

DESCRIPTION = """
User input is placed directly into a JavaScript block, outside of a string literal. This is one of the 
most CRITICAL XSS contexts because it allows direct code injection without needing to break out of strings 
or attributes. The attacker can inject arbitrary JavaScript statements that execute with full page privileges.

VULNERABILITY CONTEXT:
This occurs when server-side code embeds user data directly into JavaScript:
- <script>var user = USER_INPUT;</script>
- <script>doSomething(USER_INPUT);</script>
- <script>var config = {key: USER_INPUT};</script>
- JSONP callbacks with unvalidated names
- Dynamic script generation
- eval() with user-controllable input
- Function() constructor with user data
- setTimeout/setInterval with string arguments
- Server-side template engines embedding variables in <script> tags

Common in:
- Server-side rendering (SSR) frameworks
- Legacy PHP/ASP/JSP applications
- Analytics and tracking code
- Configuration objects
- JSONP APIs
- Dynamic module loaders

SEVERITY: CRITICAL
Direct JavaScript injection is the most dangerous XSS vector - no encoding bypasses needed.
Immediate arbitrary code execution with no user interaction required.
"""

