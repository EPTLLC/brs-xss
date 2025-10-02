#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

from .waf_types import WAFType


class WAFDetectionEngine:
    """WAF detection engine"""
    
    # Test payloads for detection
    DETECTION_PAYLOADS = [
        # Classic XSS
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        
        # SQL Injection
        "' OR 1=1 --",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users; --",
        
        # Path Traversal
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        
        # Command Injection  
        '; cat /etc/passwd',
        '| whoami',
        '`id`',
        
        # Special characters
        '<>"\'%2527%253E%253Cscript%253Ealert%2528%2529%253C%252Fscript%253E',
        '&&id',
        '||calc.exe',
        
        # Evasion tests
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script>eval("ale"+"rt(1)")</script>',
        '<svg/onload=alert(1)>',
        
        # WAF-specific tests
        '?test=<script>alert(1)</script>',
        'POST /test HTTP/1.1\r\nContent-Length: 0\r\n\r\n<script>alert(1)</script>',
    ]
    
    # Headers for fingerprinting
    WAF_HEADERS = {
        WAFType.CLOUDFLARE: [
            'cf-ray', 'cf-cache-status', 'cf-request-id', 
            'server: cloudflare', 'cf-polished'
        ],
        WAFType.AWS_WAF: [
            'x-amzn-requestid', 'x-amz-cf-id', 'x-amz-cf-pop',
            'server: cloudfront'
        ],
        WAFType.AKAMAI: [
            'akamai-ghost-ip', 'x-akamai-request-id', 'x-cache-key',
            'server: akamaighost'
        ],
        WAFType.INCAPSULA: [
            'x-iinfo', 'incap_ses', 'x-cdn', 'incapsula-incident-id'
        ],
        WAFType.SUCURI: [
            'x-sucuri-id', 'x-sucuri-cache', 'server: sucuri/cloudproxy'
        ],
        WAFType.BARRACUDA: [
            'barra_counter_session', 'bncounter', 'x-barra-counter'
        ],
        WAFType.F5_BIG_IP: [
            'bigipserver', 'x-wa-info', 'f5-ltm-pool', 'bigip'
        ],
        WAFType.FORTINET: [
            'fortigate', 'x-frame-options: fortigate'
        ],
        WAFType.MODSECURITY: [
            'mod_security', 'x-mod-security-message'
        ]
    }
    
    # Blocking patterns in response
    BLOCK_PATTERNS = {
        WAFType.CLOUDFLARE: [
            r'attention required.*cloudflare',
            r'cloudflare.*security',
            r'ray id:.*\w+'
        ],
        WAFType.AWS_WAF: [
            r'aws.*waf',
            r'access.*denied.*aws',
            r'forbidden.*amazon'
        ],
        WAFType.AKAMAI: [
            r'access.*denied.*akamai',
            r'unauthorized.*akamai',
            r'reference.*\#\d+\.\w+'
        ],
        WAFType.INCAPSULA: [
            r'incapsula.*incident',
            r'request.*unsuccessful.*incapsula',
            r'incident.*id'
        ],
        WAFType.SUCURI: [
            r'access.*denied.*sucuri',
            r'sucuri.*security',
            r'blocked.*sucuri'
        ],
        WAFType.MODSECURITY: [
            r'mod_security.*action',
            r'not.*acceptable.*mod_security'
        ]
    }