#!/usr/bin/env python3

"""
BRS-XSS JavaScript Extractor

Extraction of JavaScript code from various sources (HTML, files, etc.).

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from typing import List, Tuple, Optional
from pathlib import Path

from ..utils.logger import Logger

logger = Logger("dom.javascript_extractor")


class JavaScriptExtractor:
    """JavaScript code extractor from various sources"""
    
    @staticmethod
    def extract_from_html(html_content: str) -> List[Tuple[str, str]]:
        """
        Extract JavaScript from HTML.
        
        Args:
            html_content: HTML content
            
        Returns:
            List[(js_code, context)] - code and context
        """
        js_blocks = []
        
        # 1. Inline script tags
        script_pattern = r'<script[^>]*>(.*?)</script>'
        for match in re.finditer(script_pattern, html_content, re.DOTALL | re.IGNORECASE):
            js_code = match.group(1).strip()
            if js_code:
                js_blocks.append((js_code, "inline_script"))
        
        # 2. Event handlers in HTML attributes
        event_pattern = r'on\w+\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(event_pattern, html_content, re.IGNORECASE):
            js_code = match.group(1).strip()
            if js_code:
                js_blocks.append((js_code, "event_handler"))
        
        # 3. javascript: URLs
        js_url_pattern = r'javascript:\s*([^"\'>\s]+)'
        for match in re.finditer(js_url_pattern, html_content, re.IGNORECASE):
            js_code = match.group(1).strip()
            if js_code:
                js_blocks.append((js_code, "javascript_url"))
        
        return js_blocks
    
    @staticmethod
    def extract_from_file(file_path: str) -> List[Tuple[str, str]]:
        """
        Extract JavaScript from file.
        
        Args:
            file_path: File path
            
        Returns:
            List[(js_code, context)] - code and context
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            file_ext = Path(file_path).suffix.lower()
            
            if file_ext == '.js':
                return [(content, "js_file")]
            elif file_ext in ['.html', '.htm']:
                return JavaScriptExtractor.extract_from_html(content)
            elif file_ext in ['.php', '.asp', '.aspx', '.jsp']:
                # For server files extract only client-side JS
                return JavaScriptExtractor.extract_from_html(content)
            else:
                # Try to find JS in any file
                if '<script' in content.lower() or 'javascript:' in content.lower():
                    return JavaScriptExtractor.extract_from_html(content)
                else:
                    return [(content, "unknown")]
        
        except Exception as e:
            logger.warning(f"Error reading file {file_path}: {e}")
            return []