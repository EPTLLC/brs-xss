#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

URL/URI Context - Description
"""

TITLE = "Cross-Site Scripting (XSS) in URL/URI Context"

DESCRIPTION = """
User input is reflected within a URL, typically in href, src, action, formaction, or data attributes. 
This enables protocol-based attacks and is particularly dangerous because users may be socially engineered 
to click malicious links. Modern browsers have improved protection, but many bypass techniques exist, 
especially in mobile browsers, WebViews, and legacy systems.

VULNERABILITY CONTEXT:
Occurs when URLs contain user-controlled data:
- <a href="USER_INPUT">Link</a>
- <img src="USER_INPUT">
- <iframe src="USER_INPUT">
- <script src="USER_INPUT">
- <link href="USER_INPUT">
- <form action="USER_INPUT">
- <button formaction="USER_INPUT">
- <video src="USER_INPUT">
- <audio src="USER_INPUT">
- <embed src="USER_INPUT">
- <object data="USER_INPUT">
- <base href="USER_INPUT">
- <meta content="url=USER_INPUT">
- window.location = USER_INPUT
- window.open(USER_INPUT)

Common in:
- Redirect parameters (?redirect=URL)
- OAuth callbacks (?callback_url=URL)
- File downloads (?file=URL)
- Image galleries (?image=URL)
- RSS feed URLs
- Social media share links
- Email verification links
- Password reset links
- Deep link handlers
- Mobile app WebViews
- Browser extensions
- PDF viewers with URL parameters

SEVERITY: HIGH to CRITICAL
URL-based XSS can lead to phishing, session hijacking, and arbitrary code execution.
Social engineering makes this vector particularly effective.
"""

