#!/usr/bin/env python3

"""
Project: BRS-XSS Knowledge Base Manager
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 15:35:00 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import os
import importlib
from typing import Dict, Any, List

# --- Version Information ---
KB_VERSION = "1.0.0"
KB_BUILD = "2025.10.10"
KB_REVISION = "stable"
KB_MODULES_COUNT = 17

# --- Private variables ---
_KNOWLEDGE_BASE: Dict[str, Dict[str, str]] = {}
_initialized = False

# --- Private functions ---
def _initialize_knowledge_base():
    """Dynamically load all vulnerability details from this directory."""
    global _KNOWLEDGE_BASE, _initialized
    if _initialized:
        return

    current_dir = os.path.dirname(__file__)
    
    for filename in os.listdir(current_dir):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = filename[:-3]
            
            try:
                module = importlib.import_module(f".{module_name}", package=__name__)
                if hasattr(module, 'DETAILS'):
                    # The key for the dictionary is the filename itself
                    _KNOWLEDGE_BASE[module_name] = module.DETAILS
            except ImportError:
                # Handle potential import errors gracefully
                continue
    
    _initialized = True

# --- Public API ---
def get_vulnerability_details(context: str) -> Dict[str, str]:
    """
    Retrieves the title, description, attack vector, and remediation
    for a given vulnerability context.
    """
    _initialize_knowledge_base()
    
    context = context.lower()
    return _KNOWLEDGE_BASE.get(context, _KNOWLEDGE_BASE.get("default", {}))

# --- Public API Extensions ---
def get_kb_version() -> str:
    """Get Knowledge Base version."""
    return KB_VERSION

def get_kb_info() -> Dict[str, Any]:
    """Get KB information."""
    _initialize_knowledge_base()
    return {
        "version": KB_VERSION,
        "build": KB_BUILD,
        "revision": KB_REVISION,
        "total_contexts": len(_KNOWLEDGE_BASE),
        "available_contexts": list(_KNOWLEDGE_BASE.keys())
    }

def list_contexts() -> List[str]:
    """List all available contexts."""
    _initialize_knowledge_base()
    return sorted(_KNOWLEDGE_BASE.keys())

# --- Pre-initialize on module load ---
_initialize_knowledge_base()
