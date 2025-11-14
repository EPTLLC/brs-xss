#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Refactored
Telegram: https://t.me/easyprotech

CSS Context - Description
"""

TITLE = "Cross-Site Scripting (XSS) in CSS Context"

DESCRIPTION = """
User input is reflected within a stylesheet or a style attribute. While modern browsers have mitigated 
many classic CSS attack vectors, new techniques continue to emerge. CSS injection can lead to data 
exfiltration, UI redressing, clickjacking, and in some cases script execution through CSS-based 
keyloggers, attribute selectors for password stealing, and timing attacks.

VULNERABILITY CONTEXT:
Occurs when user input is embedded in CSS:
- <style>body {background: USER_INPUT}</style>
- <div style="USER_INPUT">content</div>
- CSS files generated from user input
- CSS-in-JS with unescaped values
- Custom CSS properties (CSS variables)
- @import rules with user URLs
- @font-face with user sources
- Inline styles from server-side rendering
- CSS preprocessors (SASS, LESS) with user input
- Style injection in SPA applications

Common in:
- Theming systems
- User profile customization
- Admin panels with CSS editors
- Email clients (HTML emails)
- Markdown renderers
- WYSIWYG editors
- CSS frameworks with dynamic generation

SEVERITY: MEDIUM to HIGH
Can lead to credential theft, data exfiltration, phishing, and UI-based attacks.
Growing threat with modern CSS features and attribute selectors.
"""

