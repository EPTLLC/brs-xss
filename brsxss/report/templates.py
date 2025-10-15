#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Fri 10 Oct 2025 14:28:00 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import json
from typing import cast,  Dict, Any, List, Optional
from datetime import datetime
from ..utils.logger import Logger

logger = Logger("report.templates")


class BaseTemplate:
    """Base template class"""
    
    def generate(self, data: Dict[str, Any]) -> str:
        """Generate full report content"""
        raise NotImplementedError
    
    def generate_summary(self, data: Dict[str, Any]) -> str:
        """Generate summary report content"""
        raise NotImplementedError


class HTMLTemplate(BaseTemplate):
    """HTML report template"""
    
    def generate(self, data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        logger.debug("Generating HTML report")
        
        # Accept dataclasses or dicts
        vulnerabilities = data.get('vulnerabilities', [])
        statistics = data.get('statistics', {})
        if hasattr(statistics, '__dict__'):
            statistics = statistics.__dict__
        target_info = data.get('target_info', {})
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BRS-XSS Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        .header {{ border-bottom: 2px solid #e74c3c; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #e74c3c; margin: 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #333; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .vulnerability {{ border: 1px solid #ddd; margin-bottom: 20px; border-radius: 5px; }}
        .vuln-header {{ background: #f8f9fa; padding: 15px; font-weight: bold; }}
        .vuln-content {{ padding: 15px; }}
        .severity-critical {{ border-left: 5px solid #dc3545; }}
        .severity-high {{ border-left: 5px solid #fd7e14; }}
        .severity-medium {{ border-left: 5px solid #ffc107; }}
        .severity-low {{ border-left: 5px solid #28a745; }}
        .payload {{ background: #f1f1f1; padding: 10px; border-radius: 3px; font-family: monospace; word-break: break-all; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BRS-XSS Security Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target: {target_info.get('url', 'Unknown')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{len(vulnerabilities)}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{statistics.get('scan_duration', 0):.1f}s</div>
                <div class="stat-label">Scan Duration</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{statistics.get('total_requests', 0)}</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{statistics.get('parameters_tested', 0)}</div>
                <div class="stat-label">Parameters Tested</div>
            </div>
        </div>
"""
        
        if vulnerabilities:
            html_content += "<h2>Vulnerabilities Found</h2>\n"
            for i, vuln in enumerate(vulnerabilities, 1):
                v = vuln.__dict__ if hasattr(vuln, '__dict__') else dict(vuln)
                sev = str(v.get('severity', 'low')).lower()
                title = v.get('title', f"Vulnerability {i}")
                url = v.get('url', 'unknown')
                param = v.get('parameter', 'unknown')
                ctx = v.get('context', 'unknown')
                desc = v.get('description', '')
                attack_vector = v.get('attack_vector', '')
                remediation = v.get('remediation', '')
                payload = v.get('payload', '')
                html_content += (
                    f"\n        <div class=\"vulnerability severity-{sev}\">\n"
                    f"            <div class=\"vuln-header\"><strong>{i}. {title}</strong></div>\n"
                    f"            <div class=\"vuln-content\">\n"
                    f"                <p><strong>Severity:</strong> <span class=\"severity-{sev}\">{sev.upper()}</span></p>\n"
                    f"                <p><strong>URL:</strong> <code>{url}</code></p>\n"
                    f"                <p><strong>Parameter:</strong> <code>{param}</code></p>\n"
                    f"                <p><strong>Context:</strong> <code>{ctx}</code></p>\n"
                    f"                <h3>Description</h3>\n"
                    f"                <p>{desc}</p>\n"
                    f"                <h3>Attack Vector</h3>\n"
                    f"                <pre><code>{attack_vector}</code></pre>\n"
                    f"                <h3>Remediation</h3>\n"
                    f"                <p>{remediation}</p>\n"
                    f"                <h3>Payload</h3>\n"
                    f"                <pre class=\"payload\"><code>{payload}</code></pre>\n"
                    f"            </div>\n"
                    f"        </div>\n"
                )
            html_content += """
    </div>
</body>
</html>"""
        
        return html_content
    
    def generate_summary(self, data: Dict[str, Any]) -> str:
        """Generate HTML summary"""
        stats = data.get('statistics', {})
        return f"""<div class="summary">
    <h3>Scan Summary</h3>
    <p>Duration: {stats.get('scan_duration', 0):.1f}s</p>
    <p>Vulnerabilities: {stats.get('vulnerabilities_found', 0)}</p>
    <p>Requests: {stats.get('total_requests', 0)}</p>
</div>"""


class JSONTemplate(BaseTemplate):
    """JSON report template"""
    
    def generate(self, data: Dict[str, Any]) -> str:
        """Generate JSON report"""
        logger.debug("Generating JSON report")
        
        # Accept dataclasses in JSON template too
        if hasattr(data.get('statistics', {}), '__dict__'):
            stats_json = data['statistics'].__dict__
        else:
            stats_json = data.get('statistics', {})
        vulns_json = []
        for v in data.get('vulnerabilities', []):
            vulns_json.append(v.__dict__ if hasattr(v, '__dict__') else v)

        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "scanner": f"BRS-XSS v{__import__('brsxss').__version__}",
                "target": data.get('target_info', {}).get('url', 'unknown')
            },
            "statistics": stats_json,
            "vulnerabilities": vulns_json,
            "summary": {
                "total_vulnerabilities": len(vulns_json),
                "risk_levels": self._count_by_severity(vulns_json)
            }
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def generate_summary(self, data: Dict[str, Any]) -> str:
        """Generate JSON summary"""
        summary = {
            "scan_summary": data.get('statistics', {}),
            "timestamp": datetime.now().isoformat()
        }
        return json.dumps(summary, indent=2)
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in counts:
                counts[severity] += 1
        return counts


class SARIFTemplate(BaseTemplate):
    """SARIF report template"""
    
    def generate(self, data: Dict[str, Any]) -> str:
        """Generate SARIF report"""
        logger.debug("Generating SARIF report")
        
        vulnerabilities = data.get('vulnerabilities', [])
        
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BRS-XSS",
                            "version": "1.0.0",
                            "organization": "EasyProTech LLC",
                            "rules": [
                                {
                                    "id": "XSS-001",
                                    "name": "CrossSiteScripting",
                                    "shortDescription": {
                                        "text": "Cross-Site Scripting vulnerability"
                                    },
                                    "fullDescription": {
                                        "text": "Potential XSS vulnerability allowing script injection"
                                    },
                                    "defaultConfiguration": {
                                        "level": "error"
                                    }
                                }
                            ]
                        }
                    },
                    "results": []
                }
            ]
        }
        
        for vuln in vulnerabilities:
            if hasattr(vuln, '__dict__'):
                vuln = vuln.__dict__
            result = {
                "ruleId": "XSS-001",
                "message": {
                    "text": f"XSS vulnerability in parameter '{vuln.get('parameter', 'unknown')}'"
                },
                "level": self._severity_to_level(vuln.get('severity', 'low')),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": vuln.get('url', 'unknown')
                            }
                        }
                    }
                ],
                "properties": {
                    "parameter": vuln.get('parameter', ''),
                    "payload": vuln.get('payload', ''),
                    "context": vuln.get('context', ''),
                    "confidence": vuln.get('confidence', 0)
                }
            }
            sarif_report["runs"][0]["results"].append(result)  # type: ignore[index]
        
        return json.dumps(sarif_report, indent=2)
    
    def generate_summary(self, data: Dict[str, Any]) -> str:
        """Generate SARIF summary"""
        return self.generate(data)
    
    def _severity_to_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        mapping = {
            "critical": "error",
            "high": "error", 
            "medium": "warning",
            "low": "note"
        }
        return mapping.get(severity.lower(), "note")


class JUnitTemplate(BaseTemplate):
    """JUnit XML report template"""
    
    def generate(self, data: Dict[str, Any]) -> str:
        """Generate JUnit XML report"""
        logger.debug("Generating JUnit XML report")
        
        vulnerabilities = data.get('vulnerabilities', [])
        statistics = data.get('statistics', {})
        
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="BRS-XSS Security Tests" tests="{len(vulnerabilities) or 1}" failures="{len(vulnerabilities)}" time="{statistics.get('scan_duration', 0)}">
    <testsuite name="XSS Vulnerability Tests" tests="{len(vulnerabilities) or 1}" failures="{len(vulnerabilities)}" time="{statistics.get('scan_duration', 0)}">
"""
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                xml_content += f"""        <testcase name="Parameter {vuln.get('parameter', f'test_{i}')}" classname="XSS.{vuln.get('context', 'unknown')}" time="0">
            <failure message="XSS vulnerability found" type="SecurityVulnerability">
URL: {vuln.get('url', 'unknown')}
Parameter: {vuln.get('parameter', 'unknown')}
Payload: {vuln.get('payload', 'unknown')}
Severity: {vuln.get('severity', 'unknown')}
Confidence: {vuln.get('confidence', 0):.1%}
            </failure>
        </testcase>
"""
        else:
            xml_content += """        <testcase name="XSS Security Test" classname="XSS.Security" time="0">
        </testcase>
"""
        
        xml_content += """    </testsuite>
</testsuites>"""
        
        return xml_content
    
    def generate_summary(self, data: Dict[str, Any]) -> str:
        """Generate JUnit summary"""
        return self.generate(data)