#!/usr/bin/env python3

"""
BRS-XSS DOM Sources and Sinks

JavaScript DOM data sources and sinks for XSS vulnerability detection.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: https://t.me/EasyProTech
"""

from typing import List, Optional


# DOM data sources
DOM_SOURCES: List[str] = [
    # URL and location objects
    'document.URL', 'document.documentURI', 'document.URLUnencoded',
    'document.baseURI', 'location.href', 'location.search', 
    'location.hash', 'location.pathname', 'location.protocol',
    'location.hostname', 'location.port',
    
    # Window objects
    'window.name', 'window.location', 'window.history',
    
    # Document objects
    'document.referrer', 'document.cookie', 'document.domain',
    
    # Storage objects
    'localStorage', 'sessionStorage', 'localStorage.getItem',
    'sessionStorage.getItem',
    
    # History API
    'history.pushState', 'history.replaceState',
    
    # PostMessage
    'postMessage', 'event.data', 'message.data',
    
    # Form and input elements
    'input.value', 'form.elements', 'formData',
    
    # WebSocket
    'WebSocket', 'websocket.send', 'websocket.onmessage',
]

# DOM data sinks
DOM_SINKS: List[str] = [
    # Code execution
    'eval', 'Function', 'setTimeout', 'setInterval',
    'execScript', 'msWriteProfilerMark',
    
    # DOM manipulation
    'innerHTML', 'outerHTML', 'insertAdjacentHTML',
    'document.write', 'document.writeln',
    'textContent', 'innerText',
    
    # Element creation
    'createElement', 'createTextNode', 'createDocumentFragment',
    
    # Attribute manipulation
    'setAttribute', 'setAttributeNode', 'setAttributeNS',
    
    # URL and navigation
    'location.assign', 'location.replace', 'window.open',
    'navigation.navigate',
    
    # Script elements
    'script.src', 'script.text', 'script.textContent',
    'script.innerText',
    
    # Event handlers
    'onclick', 'onload', 'onerror', 'onmouseover',
    'addEventListener',
    
    # Range and selection
    'Range.createContextualFragment', 'Range.insertNode',
    
    # jQuery (if used)
    '$.html', '$.append', '$.prepend', '$.after', '$.before',
    '$.replaceWith', '$.wrap', '$.wrapAll', '$.wrapInner',
    
    # Crypto
    'crypto.generateCRMFRequest',
]