#!/usr/bin/env python3

"""
BRS-XSS Message Constants

Application message constants in English (base language).
Used as keys for internationalization.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import Dict


class Messages:
    """
    Message constants class for BRS-XSS.
    All messages in English - base locale.
    """
    
    # Main application messages
    APP = {
        "welcome": "Welcome to BRS-XSS v{version}",
        "description": "XSS scanner with advanced detection capabilities",
        "author": "Developed by EasyProTech LLC",
        "exit": "BRS-XSS execution completed",
    }
    
    # Scan messages
    SCAN = {
        "started": "Started scanning target: {target}",
        "completed": "Scanning completed in {duration} seconds",
        "target_invalid": "Invalid scan target: {target}",
        "no_parameters": "No parameters found for testing",
        "parameters_found": "Found parameters for testing: {count}",
        "testing_parameter": "Testing parameter: {param}",
        "reflections_found": "Found reflections: {count}",
        "no_reflections": "No reflections found",
        "generating_payloads": "Generating payloads...",
        "payloads_generated": "Created payloads: {count}",
        "testing_payload": "Testing payload: {payload}",
        "vulnerability_found": "VULNERABILITY FOUND",
        "payload_success": "Successful payload: {payload}",
        "efficiency": "Efficiency: {efficiency}%",
        "confidence": "Confidence: {confidence}",
    }
    
    # WAF messages
    WAF = {
        "detecting": "Detecting WAF type...",
        "detected": "WAF detected: {waf_name}",
        "not_detected": "WAF not detected",
        "bypassing": "Attempting WAF bypass...",
        "bypass_success": "WAF successfully bypassed",
        "bypass_failed": "Failed to bypass WAF",
        "rate_limited": "Rate limiting triggered",
        "blocked": "Requests blocked by WAF",
    }
    
    # DOM XSS messages
    DOM = {
        "analyzing": "Analyzing DOM XSS vulnerabilities...",
        "sources_found": "Found data sources: {count}",
        "sinks_found": "Found data sinks: {count}",
        "dataflow_traced": "Analyzed data flows: {paths}",
        "vulnerability_found": "DOM XSS vulnerability found",
        "no_vulnerabilities": "No DOM XSS vulnerabilities found",
    }
    
    # Crawler messages
    CRAWLER = {
        "started": "Starting website crawling...",
        "crawling_url": "Crawling: {url}",
        "forms_found": "Found forms: {count}",
        "urls_found": "Found URLs: {count}",
        "completed": "Website crawling completed",
        "max_depth_reached": "Maximum depth reached: {depth}",
    }
    
    # ML messages
    ML = {
        "loading_model": "Loading ML model...",
        "model_loaded": "ML model loaded: {model_name}",
        "predicting": "Predicting payload effectiveness...",
        "prediction_completed": "Prediction completed",
        "training_started": "Started model training...",
        "training_completed": "Model training completed",
        "model_not_found": "ML model not found: {model_path}",
    }
    
    # API messages  
    API = {
        "server_starting": "Starting API server on {host}:{port}",
        "server_started": "API server started successfully",
        "server_stopped": "API server stopped",
        "request_received": "Request received: {method} {path}",
        "scan_queued": "Scan added to queue: {scan_id}",
    }
    
    # Error messages
    ERROR = {
        "connection_failed": "Connection error to {target}",
        "timeout": "Request timeout exceeded",
        "invalid_url": "Invalid URL: {url}",
        "file_not_found": "File not found: {file_path}",
        "permission_denied": "Permission denied",
        "config_error": "Configuration error: {error}",
        "unknown_error": "Unknown error: {error}",
        "locale_not_supported": "Locale not supported: {locale}",
    }
    
    # CLI messages
    CLI = {
        "help_scan": "Scan target for XSS vulnerabilities",
        "help_crawl": "Crawl entire website",
        "help_fuzz": "Run fuzzing mode",
        "help_api": "Start API server",
        "help_train": "Train ML model",
        "help_locale": "Change interface language",
        "help_config": "Show configuration",
        "option_url": "Target URL for scanning",
        "option_depth": "Maximum crawling depth",
        "option_threads": "Number of threads",
        "option_timeout": "Request timeout in seconds",
        "option_output": "Output file for report",
        "option_verbose": "Verbose output",
        "option_quiet": "Quiet mode",
    }
    
    # Report messages
    REPORT = {
        "generating": "Generating report...",
        "generated": "Report saved: {file_path}",
        "format_html": "HTML report with interactive charts",
        "format_json": "JSON report for automated processing",
        "format_sarif": "SARIF report for GitHub integration",
        "vulnerabilities_summary": "Found vulnerabilities: {count}",
        "scan_summary": "Scanned URLs: {urls}, parameters: {params}",
    }
    
    def get(self, message_key: str, default: str = None) -> str:
        """
        Get message by key.
        
        Args:
            message_key: Key in format "category.key" (e.g., "scan.started")
            default: Default value
            
        Returns:
            Message or default value
        """
        if "." not in message_key:
            return default or message_key
            
        category, key = message_key.split(".", 1)
        category_dict = getattr(self, category.upper(), None)
        
        if category_dict is None:
            return default or message_key
            
        return category_dict.get(key, default or message_key)
    
    def get_all_messages(self) -> Dict[str, Dict[str, str]]:
        """Get all messages as dictionary"""
        return {
            "app": self.APP,
            "scan": self.SCAN,
            "waf": self.WAF,
            "dom": self.DOM,
            "crawler": self.CRAWLER,
            "ml": self.ML,
            "api": self.API,
            "error": self.ERROR,
            "cli": self.CLI,
            "report": self.REPORT,
        }