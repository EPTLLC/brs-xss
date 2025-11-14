#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

DOM-based XSS - Description
"""

TITLE = "DOM-based Cross-Site Scripting (DOM XSS)"

DESCRIPTION = """
DOM-based XSS occurs when JavaScript code processes user-controllable data from sources like 
location.hash, location.search, postMessage, or Web Storage, and passes it to dangerous sinks like 
innerHTML, eval, or document.write without proper sanitization. Unlike reflected or stored XSS, the 
payload never touches the server - making it invisible to server-side security controls and WAFs.

This is a CLIENT-SIDE vulnerability. The attack happens entirely in the browser's JavaScript execution.
Modern web applications (SPAs, PWAs) are particularly vulnerable due to heavy client-side processing.

SEVERITY: HIGH to CRITICAL
Bypasses server-side protections. Increasingly common in modern JavaScript-heavy applications.
"""

