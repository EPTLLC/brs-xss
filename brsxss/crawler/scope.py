#!/usr/bin/env python3

"""
BRS-XSS Scope Manager

URL scope management for focused crawling with domain and path filtering.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ..utils.logger import Logger
logger = Logger("crawler.scope")


@dataclass
class ScopeRule:
    """Scope rule definition"""
    pattern: str                    # URL pattern
    rule_type: str = "include"      # include/exclude
    description: str = ""           # Rule description
    regex: bool = False             # Use regex matching


class ScopeManager:
    """
    URL scope manager for web crawling.
    
    Functions:
    - Domain-based filtering
    - Path-based filtering  
    - Regex pattern matching
    - Include/exclude rules
    - Subdomain control
    """
    
    def __init__(self, base_url: str):
        """
        Initialize scope manager.
        
        Args:
            base_url: Base URL for crawling
        """
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc.lower()
        
        # Scope rules
        self.include_rules: List[ScopeRule] = []
        self.exclude_rules: List[ScopeRule] = []
        
        # Settings
        self.allow_subdomains = True
        self.allow_external_domains = False
        self.max_path_depth = 10
        
        # Default exclusions
        self._setup_default_exclusions()
        
        # Statistics
        self.urls_checked = 0
        self.urls_allowed = 0
        self.urls_blocked = 0
    
    def _setup_default_exclusions(self):
        """Setup default URL exclusions"""
        default_exclusions = [
            # File types
            ScopeRule(r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx)$', 'exclude', 'Office documents', True),
            ScopeRule(r'\.(zip|rar|tar|gz|7z)$', 'exclude', 'Archive files', True),
            ScopeRule(r'\.(mp3|mp4|avi|mov|wmv|flv)$', 'exclude', 'Media files', True),
            ScopeRule(r'\.(jpg|jpeg|png|gif|bmp|svg|ico)$', 'exclude', 'Image files', True),
            
            # Common excludes
            ScopeRule('mailto:', 'exclude', 'Email links'),
            ScopeRule('tel:', 'exclude', 'Phone links'),
            ScopeRule('javascript:', 'exclude', 'JavaScript links'),
            ScopeRule('#', 'exclude', 'Fragment links'),
            
            # Admin areas
            ScopeRule('/admin/', 'exclude', 'Admin areas'),
            ScopeRule('/wp-admin/', 'exclude', 'WordPress admin'),
            ScopeRule('/phpmyadmin/', 'exclude', 'phpMyAdmin'),
            
            # Logout links
            ScopeRule('/logout', 'exclude', 'Logout links'),
            ScopeRule('/signout', 'exclude', 'Sign out links'),
        ]
        
        self.exclude_rules.extend(default_exclusions)
    
    def add_include_rule(self, pattern: str, description: str = "", regex: bool = False):
        """Add include rule"""
        rule = ScopeRule(pattern, 'include', description, regex)
        self.include_rules.append(rule)
        logger.debug(f"Added include rule: {pattern}")
    
    def add_exclude_rule(self, pattern: str, description: str = "", regex: bool = False):
        """Add exclude rule"""
        rule = ScopeRule(pattern, 'exclude', description, regex)
        self.exclude_rules.append(rule)
        logger.debug(f"Added exclude rule: {pattern}")
    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if URL is in scope.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is in scope
        """
        self.urls_checked += 1
        
        try:
            parsed_url = urlparse(url)
            
            # Basic validation
            if not parsed_url.scheme or not parsed_url.netloc:
                self.urls_blocked += 1
                return False
            
            # Protocol check
            if parsed_url.scheme not in ['http', 'https']:
                self.urls_blocked += 1
                return False
            
            # Domain check
            if not self._is_domain_allowed(parsed_url.netloc):
                self.urls_blocked += 1
                return False
            
            # Path depth check
            if not self._is_path_depth_allowed(parsed_url.path):
                self.urls_blocked += 1
                return False
            
            # Exclude rules check
            if self._matches_exclude_rules(url):
                self.urls_blocked += 1
                return False
            
            # Include rules check (if any)
            if self.include_rules and not self._matches_include_rules(url):
                self.urls_blocked += 1
                return False
            
            self.urls_allowed += 1
            return True
            
        except Exception as e:
            logger.error(f"Error checking scope for {url}: {e}")
            self.urls_blocked += 1
            return False
    
    def _is_domain_allowed(self, domain: str) -> bool:
        """Check if domain is allowed"""
        domain = domain.lower()
        
        # Exact match
        if domain == self.base_domain:
            return True
        
        # Subdomain check
        if self.allow_subdomains and domain.endswith('.' + self.base_domain):
            return True
        
        # External domain check
        if self.allow_external_domains:
            return True
        
        return False
    
    def _is_path_depth_allowed(self, path: str) -> bool:
        """Check if path depth is allowed"""
        if not path or path == '/':
            return True
        
        # Count path segments
        segments = [seg for seg in path.split('/') if seg]
        depth = len(segments)
        
        return depth <= self.max_path_depth
    
    def _matches_exclude_rules(self, url: str) -> bool:
        """Check if URL matches exclude rules"""
        for rule in self.exclude_rules:
            if self._matches_rule(url, rule):
                logger.debug(f"URL {url} excluded by rule: {rule.pattern}")
                return True
        return False
    
    def _matches_include_rules(self, url: str) -> bool:
        """Check if URL matches include rules"""
        for rule in self.include_rules:
            if self._matches_rule(url, rule):
                return True
        return False
    
    def _matches_rule(self, url: str, rule: ScopeRule) -> bool:
        """Check if URL matches specific rule"""
        if rule.regex:
            try:
                return bool(re.search(rule.pattern, url, re.IGNORECASE))
            except re.error:
                logger.error(f"Invalid regex pattern: {rule.pattern}")
                return False
        else:
            return rule.pattern.lower() in url.lower()
    
    def get_scope_stats(self) -> Dict[str, Any]:
        """Get scope statistics"""
        return {
            'base_url': self.base_url,
            'base_domain': self.base_domain,
            'allow_subdomains': self.allow_subdomains,
            'allow_external_domains': self.allow_external_domains,
            'max_path_depth': self.max_path_depth,
            'include_rules_count': len(self.include_rules),
            'exclude_rules_count': len(self.exclude_rules),
            'urls_checked': self.urls_checked,
            'urls_allowed': self.urls_allowed,
            'urls_blocked': self.urls_blocked,
            'allow_rate': self.urls_allowed / max(1, self.urls_checked)
        }
    
    def add_subdomain_scope(self, subdomain: str):
        """Add specific subdomain to scope"""
        full_domain = f"{subdomain}.{self.base_domain}"
        self.add_include_rule(full_domain, f"Subdomain: {subdomain}")
    
    def add_path_scope(self, path_pattern: str):
        """Add specific path pattern to scope"""
        self.add_include_rule(path_pattern, f"Path pattern: {path_pattern}")
    
    def exclude_file_types(self, extensions: List[str]):
        """Exclude specific file types"""
        for ext in extensions:
            pattern = f'\\.{ext}$'
            self.add_exclude_rule(pattern, f"File type: {ext}", regex=True)
    
    def set_strict_mode(self):
        """Enable strict mode (exact domain only)"""
        self.allow_subdomains = False
        self.allow_external_domains = False
        self.max_path_depth = 5
        logger.info("Strict scope mode enabled")
    
    def set_permissive_mode(self):
        """Enable permissive mode"""
        self.allow_subdomains = True
        self.allow_external_domains = True
        self.max_path_depth = 20
        logger.info("Permissive scope mode enabled")