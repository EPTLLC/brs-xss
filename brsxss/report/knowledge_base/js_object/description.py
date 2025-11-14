#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

JavaScript Object Context - Description
"""

TITLE = "Cross-Site Scripting (XSS) in JavaScript Object Context"

DESCRIPTION = """
User input is reflected within a JavaScript object literal without proper sanitization. This allows 
attackers to inject additional properties, methods, or break out of the object context to execute 
arbitrary code. Modern JavaScript frameworks and template engines are particularly vulnerable if they 
dynamically construct objects from user input.

VULNERABILITY CONTEXT:
Occurs when user data is embedded in object literals:
- <script>var config = {key: USER_INPUT};</script>
- <script>var user = {name: 'USER_INPUT'};</script>
- <script>var obj = USER_INPUT;</script>
- JSON.parse() with user-controlled strings
- Object.assign() with untrusted sources
- Spread operator with user objects {...userInput}
- Dynamic property names {[USER_INPUT]: value}
- Method definitions {[USER_INPUT]() {}}

Common in:
- Configuration objects from server
- User profile data
- API responses embedded in pages
- State management (Redux, Vuex)
- GraphQL responses
- WebSocket messages
- PostMessage data
- LocalStorage/SessionStorage data

SEVERITY: CRITICAL
Can lead to prototype pollution, property injection, and arbitrary code execution.
Modern attack vector increasingly exploited in Node.js and browser applications.
"""

