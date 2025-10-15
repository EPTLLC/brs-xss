#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 13:58:30 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import os
import yaml  # type: ignore[import-untyped]
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

from ..utils.logger import Logger
logger = Logger("core.config_manager")


class ConfigManager:
    """
    Configuration manager for BRS-XSS.
    
    Features:
    - YAML configuration loading
    - Environment variable override
    - Configuration validation
    - Default value management
    - Runtime configuration updates
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager"""
        # Respect environment-provided config paths first
        env_config_path = os.getenv("BRS_XSS_CONFIG_PATH")
        self.config_path = config_path or env_config_path or self._find_config_file()
        self.user_config_path = os.getenv("BRS_XSS_USER_CONFIG_PATH")
        self.config_data: Dict[str, Any] = {}
        self.defaults = self._load_defaults()
        
        # Load configuration
        self._load_config()
    
    def _find_config_file(self) -> str:
        """Find configuration file"""
        possible_paths = [
            'config/default.yaml',
            'config/config.yaml',
            'brsxss.yaml',
            'config.yaml'
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                return path
        
        # Return default path even if doesn't exist
        return 'config/default.yaml'
    
    def _load_config(self):
        """Load configuration from file"""
        loaded_config: Dict[str, Any] = {}

        # Load base YAML config
        try:
            if self.config_path and Path(self.config_path).exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded_config = yaml.safe_load(f) or {}
                logger.info(f"Configuration loaded from: {self.config_path}")
            else:
                logger.warning(f"Configuration file not found: {self.config_path}")
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")

        # Merge defaults -> base config
        merged = self._merge_configs(self.defaults, loaded_config)

        # Load and merge user config (TOML) if provided
        try:
            if self.user_config_path and Path(self.user_config_path).exists():
                user_cfg = self._load_user_config(self.user_config_path)
                merged = self._merge_configs(merged, user_cfg)
                logger.info(f"User configuration loaded from: {self.user_config_path}")
        except Exception as e:
            logger.warning(f"User configuration load failed: {e}")

        self.config_data = merged

        # Apply environment overrides (BRSXSS_*)
        self._apply_env_overrides()
    
    def _load_defaults(self) -> Dict[str, Any]:
        """Load default configuration values"""
        return {
            'scanner': {
                'timeout': 15,
                'max_depth': 3,
                'max_urls': 1000,
                'max_concurrent': 10,
                'request_timeout': 10,
                'request_delay': 0.1,
                'max_payloads_per_param': 20,
                'min_vulnerability_score': 0.2,
                'user_agent': 'BRS-XSS Scanner v1.0'
            },
            'crawler': {
                'max_depth': 3,
                'max_urls': 1000,
                'follow_redirects': True,
                'extract_forms': True,
                'extract_links': True,
                'extract_ajax': True,
                'request_delay': 0.1
            },
            'payloads': {
                'max_length': 1000,
                'use_encoding': True,
                'use_evasion': True,
                'custom_payloads': []
            },
            'waf': {
                'detection_enabled': True,
                'evasion_enabled': True,
                'max_evasion_attempts': 50
            },
            'reporting': {
                'format': 'html',
                'output_dir': 'reports',
                'include_screenshots': False,
                'include_request_response': True
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/brsxss.log',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'ml': {
                'enabled': False,
                'model_path': 'models/',
                'training_data_path': 'data/training/',
                'prediction_threshold': 0.7
            }
        }
    
    def _merge_configs(self, default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge configuration dictionaries"""
        result = default.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides"""
        env_mappings = {
            'BRSXSS_MAX_DEPTH': 'scanner.max_depth',
            'BRSXSS_MAX_URLS': 'scanner.max_urls',
            'BRSXSS_MAX_CONCURRENT': 'scanner.max_concurrent',
            'BRSXSS_REQUEST_TIMEOUT': 'scanner.request_timeout',
            'BRSXSS_REQUEST_DELAY': 'scanner.request_delay',
            'BRSXSS_USER_AGENT': 'scanner.user_agent',
            'BRSXSS_OUTPUT_FORMAT': 'reporting.format',
            'BRSXSS_OUTPUT_DIR': 'reporting.output_dir',
            'BRSXSS_LOG_LEVEL': 'logging.level',
            'BRSXSS_LOG_FILE': 'logging.file'
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                self._set_nested_value(config_path, self._convert_env_value(env_value))
                logger.debug(f"Environment override: {config_path} = {env_value}")
    
    def _set_nested_value(self, path: str, value: Any):
        """Set nested configuration value using dot notation"""
        keys = path.split('.')
        current = self.config_data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _convert_env_value(self, value: str) -> Union[str, int, float, bool]:
        """Convert environment variable string to appropriate type"""
        # Boolean conversion
        if value.lower() in ('true', 'yes', '1', 'on'):
            return True
        elif value.lower() in ('false', 'no', '0', 'off'):
            return False
        
        # Numeric conversion
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # Return as string
        return value

    def _load_user_config(self, path: str) -> Dict[str, Any]:
        """Load user configuration from TOML file with safe fallbacks."""
        # Prefer stdlib tomllib when available (Py>=3.11)
        try:
            import tomllib
            with open(path, 'rb') as f:
                return tomllib.load(f) or {}
        except Exception:
            # Try tomli if installed
            try:
                import tomli
                with open(path, 'rb') as f:
                    return tomli.load(f) or {}
            except Exception:
                # Minimal parser for simple key=value under [section]
                with open(path, 'r', encoding='utf-8') as f:
                    text = f.read()
                return self._parse_simple_toml(text)

    def _parse_simple_toml(self, text: str) -> Dict[str, Any]:
        """Very small TOML subset parser supporting [section] and key=value.
        Supports ints, floats, booleans, quoted strings, and simple string arrays.
        """
        result: Dict[str, Any] = {}
        current: Dict[str, Any] = result
        current_section: Optional[str] = None

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1].strip()
                if not section:
                    continue
                current_section = section
                if section not in result:
                    result[section] = {}
                current = result[section]
                continue
            if '=' not in line:
                continue
            key, val = line.split('=', 1)
            key = key.strip()
            val = val.strip()

            # Strip comments at end of line
            if '#' in val:
                val = val.split('#', 1)[0].strip()

            # Parse value
            parsed: Any
            if val.startswith('[') and val.endswith(']'):
                # Simple array of strings/numbers
                inner = val[1:-1].strip()
                items: List[Any] = []
                if inner:
                    for part in inner.split(','):
                        items.append(self._parse_simple_toml_value(part.strip()))
                parsed = items
            else:
                parsed = self._parse_simple_toml_value(val)

            current[key] = parsed

        return result

    def _parse_simple_toml_value(self, val: str) -> Any:
        """Parse a single TOML primitive value for the simple parser."""
        if not val:
            return ""
        if val.lower() in ('true', 'false'):
            return val.lower() == 'true'
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            return val[1:-1]
        try:
            if '.' in val:
                return float(val)
            return int(val)
        except ValueError:
            return val
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'scanner.max_depth')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        current = self.config_data
        
        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'scanner.max_depth')
            value: Value to set
        """
        self._set_nested_value(key, value)
        logger.debug(f"Configuration updated: {key} = {value}")
    
    def update(self, updates: Dict[str, Any]):
        """
        Update multiple configuration values.
        
        Args:
            updates: Dictionary of updates in dot notation
        """
        for key, value in updates.items():
            self.set(key, value)
    
    def save(self, path: Optional[str] = None):
        """
        Save configuration to file.
        
        Args:
            path: Output path (defaults to current config path)
        """
        output_path = path or self.config_path
        
        try:
            # Create directory if needed
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration saved to: {output_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
    
    def reload(self):
        """Reload configuration from file"""
        self._load_config()
        logger.info("Configuration reloaded")
    
    def validate(self) -> List[str]:
        """
        Validate configuration values.
        
        Returns:
            List of validation errors
        """
        errors = []
        
        # Validate scanner settings
        scanner_config = self.get('scanner', {})
        
        if scanner_config.get('max_depth', 0) < 1:
            errors.append("scanner.max_depth must be >= 1")
        
        if scanner_config.get('max_urls', 0) < 1:
            errors.append("scanner.max_urls must be >= 1")
        
        if scanner_config.get('max_concurrent', 0) < 1:
            errors.append("scanner.max_concurrent must be >= 1")
        
        if scanner_config.get('request_timeout', 0) < 1:
            errors.append("scanner.request_timeout must be >= 1")
        
        if scanner_config.get('request_delay', -1) < 0:
            errors.append("scanner.request_delay must be >= 0")
        
        # Validate crawler settings
        crawler_config = self.get('crawler', {})
        
        if crawler_config.get('max_depth', 0) < 1:
            errors.append("crawler.max_depth must be >= 1")
        
        if crawler_config.get('max_urls', 0) < 1:
            errors.append("crawler.max_urls must be >= 1")
        
        # Validate reporting settings
        reporting_config = self.get('reporting', {})
        
        valid_formats = ['html', 'json', 'xml', 'sarif', 'csv']
        report_format = reporting_config.get('format', 'html')
        if report_format not in valid_formats:
            errors.append(f"reporting.format must be one of: {', '.join(valid_formats)}")
        
        # Validate logging settings
        logging_config = self.get('logging', {})
        
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        log_level = logging_config.get('level', 'INFO')
        if log_level not in valid_levels:
            errors.append(f"logging.level must be one of: {', '.join(valid_levels)}")
        
        return errors
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section.
        
        Args:
            section: Section name (e.g., 'scanner')
            
        Returns:
            Section configuration
        """
        return self.get(section, {})
    
    def has(self, key: str) -> bool:
        """
        Check if configuration key exists.
        
        Args:
            key: Configuration key
            
        Returns:
            True if key exists
        """
        return self.get(key) is not None
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for debugging"""
        return {
            'config_path': self.config_path,
            'config_exists': Path(self.config_path).exists(),
            'sections': list(self.config_data.keys()),
            'validation_errors': self.validate()
        }