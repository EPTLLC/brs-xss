# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 09:03:08 MSK
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
SARIF 2.1.0 compliant reporter for GitHub Code Scanning integration
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Any
from urllib.parse import urlparse

from .data_models import VulnerabilityData


class SARIFReporter:
    """Generate SARIF 2.1.0 compliant reports for security tools integration"""
    
    def __init__(self):
        from .. import __version__
        self.version = __version__
        self.tool_name = "BRS-XSS"
        self.vendor = "EasyProTech LLC"
        
    def generate_sarif(self, vulnerabilities: List[VulnerabilityData], 
                      scan_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate complete SARIF 2.1.0 report"""
        
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": self._build_tool_info(),
                    "invocation": self._build_invocation(scan_info),
                    "artifacts": self._build_artifacts(vulnerabilities),
                    "results": self._build_results(vulnerabilities),
                    "taxonomies": [self._build_taxonomy()],
                    "properties": {
                        "scan_statistics": {
                            "targets_scanned": scan_info.get("targets_scanned", 0),
                            "vulnerabilities_found": len(vulnerabilities),
                            "scan_duration": scan_info.get("duration", "unknown"),
                            "false_positive_rate": scan_info.get("false_positive_rate", "unknown")
                        }
                    }
                }
            ]
        }
        
        return sarif_report
    
    def _build_tool_info(self) -> Dict[str, Any]:
        """Build SARIF tool information section"""
        return {
            "driver": {
                "name": self.tool_name,
                "version": self.version,
                "semanticVersion": self.version,
                "informationUri": "https://github.com/EPTLLC/brs-xss",
                "organization": self.vendor,
                "shortDescription": {
                    "text": "Context-aware async XSS scanner for CI"
                },
                "fullDescription": {
                    "text": "BRS-XSS scanner with context detection, async performance, and multi-format reporting."
                },
                "rules": self._build_rules(),
                "supportedTaxonomies": [
                    {
                        "name": "CWE",
                        "index": 0,
                        "guid": "25F72D7E-8A92-459D-B67A-64B6F3C2F1B4"
                    }
                ]
            }
        }
    
    def _build_rules(self) -> List[Dict[str, Any]]:
        """Build SARIF rules for different XSS types"""
        return [
            {
                "id": "XSS001",
                "name": "ReflectedXSS",
                "shortDescription": {"text": "Reflected Cross-Site Scripting"},
                "fullDescription": {
                    "text": "User input is reflected in the response without proper sanitization, allowing script injection."
                },
                "help": {"text": "Sanitize user input and encode output appropriately. See CWE-79."},
                "helpUri": "https://cwe.mitre.org/data/definitions/79.html",
                "messageStrings": {
                    "default": {
                        "text": "Reflected XSS vulnerability detected in parameter '{0}' with payload '{1}'"
                    }
                },
                "defaultConfiguration": {"level": "error"},
                "properties": {
                    "security-severity": "8.8",
                    "precision": "high",
                    "tags": ["security", "external/cwe/cwe-79"]
                },
                "relationships": [
                    {
                        "target": {
                            "id": "79",
                            "index": 0,
                            "toolComponent": {
                                "name": "CWE",
                                "index": 0
                            }
                        },
                        "kinds": ["superset"]
                    }
                ]
            },
            {
                "id": "XSS002",
                "name": "StoredXSS",
                "shortDescription": {"text": "Stored Cross-Site Scripting"},
                "fullDescription": {
                    "text": "User input is stored and later displayed without proper sanitization, allowing persistent script injection."
                },
                "help": {"text": "Validate and sanitize stored user input. Apply output encoding. See CWE-79."},
                "helpUri": "https://cwe.mitre.org/data/definitions/79.html",
                "messageStrings": {
                    "default": {
                        "text": "Stored XSS vulnerability detected in parameter '{0}' with payload '{1}'"
                    }
                },
                "defaultConfiguration": {"level": "error"},
                "properties": {
                    "security-severity": "9.0",
                    "precision": "high",
                    "tags": ["security", "external/cwe/cwe-79"]
                }
            },
            {
                "id": "XSS003",
                "name": "DOMXSS",
                "shortDescription": {"text": "DOM-based Cross-Site Scripting"},
                "fullDescription": {
                    "text": "Client-side JavaScript processes user input unsafely, allowing script injection through DOM manipulation."
                },
                "help": {"text": "Avoid using untrusted input in DOM sinks. Use safe APIs. See CWE-79."},
                "helpUri": "https://cwe.mitre.org/data/definitions/79.html",
                "messageStrings": {
                    "default": {
                        "text": "DOM XSS vulnerability detected with source '{0}' and sink '{1}'"
                    }
                },
                "defaultConfiguration": {"level": "error"},
                "properties": {
                    "security-severity": "8.5",
                    "precision": "medium",
                    "tags": ["security", "external/cwe/cwe-79", "dom"]
                }
            }
        ]
    
    def _build_invocation(self, scan_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build SARIF invocation information"""
        return {
            "executionSuccessful": True,
            "startTimeUtc": scan_info.get("start_time", datetime.now(timezone.utc).isoformat()),
            "endTimeUtc": scan_info.get("end_time", datetime.now(timezone.utc).isoformat()),
            "machine": scan_info.get("machine", "unknown"),
            "commandLine": scan_info.get("command_line", "brs-xss scan"),
            "workingDirectory": {
                "uri": scan_info.get("working_directory", "file:///")
            }
        }
    
    def _build_artifacts(self, vulnerabilities: List[VulnerabilityData]) -> List[Dict[str, Any]]:
        """Build SARIF artifacts (scanned URLs)"""
        artifacts = []
        seen_urls = set()
        
        for vuln in vulnerabilities:
            parsed_url = urlparse(vuln.url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            if base_url not in seen_urls:
                artifacts.append({
                    "location": {
                        "uri": base_url
                    },
                    "mimeType": "text/html",
                    "properties": {
                        "scanned": True,
                        "parameters": parsed_url.query
                    }
                })
                seen_urls.add(base_url)
        
        return artifacts
    
    def _build_results(self, vulnerabilities: List[VulnerabilityData]) -> List[Dict[str, Any]]:
        """Build SARIF results from vulnerabilities"""
        results: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            rule_id = self._get_rule_id(vuln)
            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": self._get_rule_index(rule_id),
                "message": {
                    "id": "default",
                    "arguments": [
                        vuln.parameter or "unknown",
                        vuln.payload[:100] + "..." if len(vuln.payload) > 100 else vuln.payload,
                    ],
                },
                "level": self._get_severity_level(vuln.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": self._get_base_url(vuln.url)},
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                                "snippet": {"text": f"Parameter: {vuln.parameter}, Payload: {vuln.payload}"},
                            },
                        },
                        "logicalLocations": [
                            {"name": vuln.parameter or "unknown_parameter", "kind": "parameter"}
                        ],
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": str(hash(f"{vuln.url}{vuln.parameter}{vuln.payload}"))[:16]
                },
                "properties": {
                    "confidence": vuln.confidence,
                    "context_type": vuln.context_type,
                    "vulnerability_type": vuln.vulnerability_type,
                    "url": vuln.url,
                    "parameter": vuln.parameter,
                    "payload": vuln.payload,
                    # Optional fields; not all data models include http method
                    "method": getattr(vuln, "method", "unknown"),
                    "scan_engine": vuln.scan_engine,
                },
                "fixes": [
                    {
                        "description": {
                            "text": f"Sanitize input for parameter '{vuln.parameter}' in {vuln.context_type} context"
                        },
                        "artifactChanges": [
                            {
                                "artifactLocation": {"uri": self._get_base_url(vuln.url)},
                                "replacements": [
                                    {
                                        "deletedRegion": {"startLine": 1, "startColumn": 1},
                                        "insertedContent": {
                                            "text": f"// TODO: Sanitize parameter '{vuln.parameter}' for {vuln.context_type} context"
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
            # Recommended additional metadata
            result["properties"]["tags"] = ["xss", vuln.vulnerability_type]
            results.append(result)
        return results
    
    def _build_taxonomy(self) -> Dict[str, Any]:
        """Build CWE taxonomy reference"""
        return {
            "name": "CWE",
            "version": "4.12",
            "informationUri": "https://cwe.mitre.org/data/published/cwe_v4.12.pdf/",
            "downloadUri": "https://cwe.mitre.org/data/xml/cwec_v4.12.xml.zip",
            "organization": "MITRE",
            "shortDescription": {
                "text": "The MITRE Common Weakness Enumeration"
            },
            "taxa": [
                {
                    "id": "79",
                    "name": "CWE-79",
                    "shortDescription": {
                        "text": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
                    },
                    "fullDescription": {
                        "text": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."
                    }
                }
            ]
        }
    
    def _get_rule_id(self, vuln: VulnerabilityData) -> str:
        """Determine rule ID based on vulnerability type"""
        if vuln.vulnerability_type == 'stored_xss':
            return "XSS002"
        elif vuln.vulnerability_type == 'dom_xss':
            return "XSS003"
        return "XSS001"  # Default to reflected
    
    def _get_rule_index(self, rule_id: str) -> int:
        """Get rule index for SARIF reference"""
        rule_indices = {"XSS001": 0, "XSS002": 1, "XSS003": 2}
        return rule_indices.get(rule_id, 0)
    
    def _get_severity_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        severity_map = {
            "critical": "error",
            "high": "error", 
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        return severity_map.get(severity.lower(), "warning")
    
    def _get_base_url(self, url: str) -> str:
        """Extract base URL without query parameters"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def save_sarif(self, vulnerabilities: List[VulnerabilityData], 
                   scan_info: Dict[str, Any], output_path: str) -> None:
        """Save SARIF report to file"""
        sarif_report = self.generate_sarif(vulnerabilities, scan_info)
        # Add run-wide recommended properties
        if sarif_report.get("runs"):
            sarif_report["runs"][0].setdefault("columnKind", "utf16CodeUnits")
            sarif_report["runs"][0].setdefault("defaultEncoding", "utf-8")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2, ensure_ascii=False)
