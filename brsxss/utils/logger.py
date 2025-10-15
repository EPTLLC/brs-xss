#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import logging
import sys
from typing import Optional
from pathlib import Path

from rich.logging import RichHandler


class ColorFormatter(logging.Formatter):
    """Colored log formatter"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'SUCCESS': '\033[92m',  # Bright Green
    }
    
    RESET = '\033[0m'
    
    def format(self, record):
        if hasattr(record, 'levelname'):
            color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        
        return super().format(record)


class Logger:
    """
    logger for BRS-XSS.
    
    Features:
    - Colored console output
    - File logging support
    - Custom log levels
    - Structured logging
    - Performance tracking
    """
    
    _configured = False

    def __init__(self, name: str, level: str = "WARNING"):
        """Initialize logger"""
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
        
        # Add custom SUCCESS level
        if not hasattr(logging, 'SUCCESS'):
            logging.addLevelName(25, 'SUCCESS')
    
    def _setup_handlers(self):
        """Setup log handlers"""
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        
        console_formatter = ColorFormatter(
            '%(message)s'  # Simplified format for cleaner output
        )
        console_handler.setFormatter(console_formatter)
        
        self.logger.addHandler(console_handler)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(message, **kwargs)
    
    def success(self, message: str, **kwargs):
        """Log success message"""
        self.logger.log(25, message, **kwargs)
    
    def add_file_handler(self, file_path: str, level: str = "INFO"):
        """Add file logging handler"""
        try:
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(file_path, encoding='utf-8')
            file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
            
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            
            self.logger.addHandler(file_handler)
            self.info(f"File logging enabled: {file_path}")
            
        except Exception as e:
            self.error(f"Failed to setup file logging: {e}")
    
    def set_level(self, level: str):
        """Set logging level"""
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    @staticmethod
    def configure_logging(verbose: bool = False, log_file: Optional[str] = None):
        """Configure global logging settings based on verbosity."""
        if Logger._configured:
            return

        level = "INFO" if verbose else "WARNING"
        
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # Clear existing handlers to prevent conflicts
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Use RichHandler for beautiful, conflict-free console logging
        rich_handler = RichHandler(
            show_path=False,
            log_time_format="[%X]", # e.g., [14:32:56]
            level=level,
            show_level=verbose, # Only show level name in verbose mode
            show_time=verbose   # Only show timestamp in verbose mode
        )
        root_logger.addHandler(rich_handler)

        if log_file:
            try:
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(file_formatter)
                root_logger.addHandler(file_handler)
            except Exception as e:
                # Use print here since logger might not be fully configured
                print(f"Error setting up file logger: {e}")

        Logger._configured = True
    
    @staticmethod
    def setup_global_logging(level: str = "INFO", log_file: Optional[str] = None):
        """Setup global logging configuration"""
        # Clear existing handlers to prevent duplication
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Set root logger level but don't add handlers (we use custom loggers)
        root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        
        if log_file:
            try:
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(file_formatter)
                root_logger.addHandler(file_handler)
            except Exception as e:
                print(f"Failed to setup file logging: {e}")


# Global logger instance
def get_logger(name: str) -> Logger:
    """Get logger instance"""
    # Default level is now WARNING, will be overridden by global config
    return Logger(name, level="WARNING")