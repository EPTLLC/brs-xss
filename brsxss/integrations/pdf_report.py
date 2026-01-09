"""
BRS-XSS PDF Report Generator
Generates professional PDF reports using HTML/CSS -> PDF

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-12-26
"""

import base64
from datetime import datetime
from typing import Any, Optional
from dataclasses import dataclass
from pathlib import Path

# v4.0.0 Classification Rules
try:
    from ..core import classification_rules  # noqa: F401

    CLASSIFICATION_RULES_AVAILABLE = True
except ImportError:
    CLASSIFICATION_RULES_AVAILABLE = False

# v4.0.0 Phase 9: Unified Finding Normalization
try:
    from ..core.finding_normalizer import prepare_findings_for_report

    NORMALIZER_AVAILABLE = True
except ImportError:
    NORMALIZER_AVAILABLE = False


@dataclass
class VulnItem:
    """Vulnerability for report"""

    severity: str
    url: str
    parameter: str
    payload: str
    context: str
    evidence: str = ""


class PDFReportGenerator:
    """
    Generate PDF reports for BRS-XSS

    Uses weasyprint for HTML->PDF conversion
    Falls back to simple text if weasyprint unavailable
    """

    # Colors
    COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#16a34a",
        "info": "#2563eb",
        "bg": "#0f0f0f",
        "surface": "#1a1a1a",
        "border": "#2a2a2a",
        "text": "#e5e5e5",
        "muted": "#737373",
        "accent": "#f97316",
    }

    # Legal footer for every page
    LEGAL_FOOTER = "BRS-XSS | EasyProTech LLC | Authorized testing only | easypro.tech"

    CSS = """
    /* Enterprise-grade PDF - seamless full bleed dark theme */
    @page {
        size: A4;
        margin: 0;
        background: #0a0a0a;
    }
    
    @page:first {
        margin-top: 0;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    html, body {
        margin: 0;
        padding: 0;
        background: #0a0a0a;
        color: #d4d4d4;
    }
    
    body {
        font-family: 'Noto Sans', 'Noto Sans CJK SC', 'Noto Sans CJK JP', 'Noto Sans CJK KR', 
                     'Noto Sans Arabic', 'Noto Sans Hebrew', 'Noto Sans Thai', 'Noto Sans Devanagari',
                     'DejaVu Sans', sans-serif;
        font-size: 10pt;
        line-height: 1.7;
        background: #0a0a0a;
        padding: 0;
    }
    
    .document {
        background: #0a0a0a;
        min-height: 100vh;
    }
    
    .content {
        padding: 35pt 45pt;
    }
    
    .header {
        text-align: center;
        padding: 45pt 45pt 35pt 45pt;
        background: #0a0a0a;
        border-bottom: 1pt solid #1a1a1a;
    }
    
    .header .logo {
        width: 80pt;
        height: 80pt;
        border-radius: 50%;
        margin-bottom: 18pt;
        border: 2pt solid #f97316;
    }
    
    .header .company {
        color: #525252;
        font-size: 8pt;
        text-transform: uppercase;
        letter-spacing: 3pt;
        margin-bottom: 10pt;
    }
    
    .header h1 {
        color: #f97316;
        font-size: 24pt;
        font-weight: 700;
        margin: 0 0 10pt 0;
        letter-spacing: 0.5pt;
    }
    
    .header .subtitle {
        color: #737373;
        font-size: 9pt;
        letter-spacing: 0.5pt;
    }
    
    .section {
        background: #0f0f0f;
        padding: 20pt 25pt;
        margin: 0 0 2pt 0;
        page-break-inside: avoid;
    }
    
    .section:nth-child(even) {
        background: #0a0a0a;
    }
    
    .section h2 {
        color: #f97316;
        font-size: 11pt;
        font-weight: 600;
        margin: 0 0 15pt 0;
        padding-bottom: 10pt;
        border-bottom: 1pt solid #1a1a1a;
        text-transform: uppercase;
        letter-spacing: 1.5pt;
    }
    
    .grid {
        display: table;
        width: 100%;
    }
    
    .grid-row {
        display: table-row;
    }
    
    .grid-cell {
        display: table-cell;
        padding: 8pt 15pt;
        border-bottom: 1pt solid #141414;
        vertical-align: top;
    }
    
    .grid-cell.label {
        color: #525252;
        width: 35%;
        font-weight: 500;
        font-size: 9pt;
        text-transform: uppercase;
        letter-spacing: 0.5pt;
    }
    
    .grid-cell.value {
        color: #e5e5e5;
    }
    
    .vuln {
        background: #0f0f0f;
        border-left: 3pt solid;
        padding: 15pt 20pt;
        margin: 0;
        page-break-inside: avoid;
    }
    
    .vuln:nth-child(even) {
        background: #0a0a0a;
    }
    
    .vuln.critical { border-color: #dc2626; }
    .vuln.high { border-color: #ea580c; }
    .vuln.medium { border-color: #ca8a04; }
    .vuln.low { border-color: #16a34a; }
    
    .vuln-header {
        display: table;
        width: 100%;
        margin-bottom: 10pt;
    }
    
    .severity {
        font-weight: 600;
        text-transform: uppercase;
        font-size: 7pt;
        padding: 4pt 10pt;
        letter-spacing: 1pt;
    }
    
    .severity.critical { background: #dc2626; color: #fef2f2; }
    .severity.high { background: #ea580c; color: #fff7ed; }
    .severity.medium { background: #ca8a04; color: #0a0a0a; }
    .severity.low { background: #16a34a; color: #f0fdf4; }
    
    code {
        background: #141414;
        padding: 2pt 6pt;
        font-family: 'Noto Sans Mono', 'DejaVu Sans Mono', 'Consolas', monospace;
        font-size: 9pt;
        word-break: break-all;
        color: #f97316;
    }
    
    pre {
        background: #0f0f0f;
        padding: 15pt 20pt;
        font-family: 'Noto Sans Mono', 'DejaVu Sans Mono', monospace;
        font-size: 9pt;
        line-height: 1.5;
        color: #a3a3a3;
        border-left: 2pt solid #262626;
        margin: 12pt 0;
    }
    
    .stats {
        display: table;
        width: 100%;
        text-align: center;
        background: #0a0a0a;
    }
    
    .stat {
        display: table-cell;
        padding: 25pt 15pt;
        background: #0a0a0a;
        border-right: 1pt solid #141414;
    }
    
    .stat:last-child {
        border-right: none;
    }
    
    .stat-value {
        font-size: 32pt;
        font-weight: 700;
        color: #f97316;
        line-height: 1;
    }
    
    .stat-label {
        font-size: 8pt;
        color: #525252;
        text-transform: uppercase;
        letter-spacing: 1.5pt;
        margin-top: 8pt;
    }
    
    .footer {
        text-align: center;
        padding: 30pt 45pt;
        background: #0a0a0a;
        color: #3f3f3f;
        font-size: 8pt;
        letter-spacing: 0.5pt;
    }
    
    /* Typography for markdown content - seamless flow */
    h1 { color: #f97316; font-size: 16pt; font-weight: 700; padding: 25pt 45pt 15pt 45pt; margin: 0; background: #0a0a0a; }
    h2 { color: #f97316; font-size: 13pt; font-weight: 600; padding: 20pt 45pt 12pt 45pt; margin: 0; background: #0f0f0f; border-bottom: none; }
    h3 { color: #e5e5e5; font-size: 11pt; font-weight: 600; padding: 15pt 45pt 10pt 45pt; margin: 0; background: #0a0a0a; }
    h4 { color: #a3a3a3; font-size: 10pt; font-weight: 500; padding: 12pt 45pt 8pt 45pt; margin: 0; }
    
    p { padding: 6pt 45pt; margin: 0; color: #d4d4d4; background: #0a0a0a; }
    
    ul, ol { padding: 8pt 45pt 8pt 70pt; margin: 0; color: #d4d4d4; background: #0a0a0a; }
    li { margin: 0; padding: 3pt 0; line-height: 1.6; }
    
    strong, b { color: #f97316; font-weight: 600; }
    em, i { color: #737373; }
    
    blockquote {
        border-left: 2pt solid #f97316;
        margin: 0;
        padding: 12pt 45pt 12pt 43pt;
        background: #0f0f0f;
        color: #737373;
        font-style: italic;
    }
    
    hr {
        border: none;
        height: 1pt;
        background: #1a1a1a;
        margin: 0;
    }
    
    a { color: #f97316; text-decoration: none; }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 12pt 45pt;
        background: #0a0a0a;
    }
    
    th, td {
        padding: 10pt 15pt;
        border-bottom: 1pt solid #1a1a1a;
        text-align: left;
    }
    
    th {
        background: #0f0f0f;
        color: #f97316;
        font-weight: 600;
        font-size: 8pt;
        text-transform: uppercase;
        letter-spacing: 1pt;
    }
    
    td {
        background: #0a0a0a;
        color: #d4d4d4;
    }
    
    tr:nth-child(even) td {
        background: #0f0f0f;
    }
    
    .warning-box {
        background: #0f0808;
        border-left: 3pt solid #dc2626;
        padding: 15pt 45pt 15pt 42pt;
        margin: 0;
        color: #fca5a5;
    }
    
    .info-box {
        background: #080a0f;
        border-left: 3pt solid #3b82f6;
        padding: 15pt 45pt 15pt 42pt;
        margin: 0;
        color: #93c5fd;
    }
    
    /* Page break control */
    .page-break {
        page-break-before: always;
    }
    
    .no-break {
        page-break-inside: avoid;
    }
    """

    def __init__(self):
        self._weasyprint = None
        self._logo_b64 = None

        try:
            import weasyprint

            self._weasyprint = weasyprint
        except ImportError:
            pass

        # Load logo as base64
        logo_path = Path(__file__).parent / "logo.png"
        if logo_path.exists():
            self._logo_b64 = base64.b64encode(logo_path.read_bytes()).decode("utf-8")

    def generate_recon_report(
        self, scan_id: str, target: str, profile: dict[str, Any]
    ) -> bytes:
        """Generate reconnaissance PDF report"""
        html = self._build_recon_html(scan_id, target, profile)
        return self._html_to_pdf(html)

    def generate_scan_report(
        self,
        scan_id: str,
        target: str,
        mode: str,
        duration: float,
        proxy: str,
        vulns,
        recon: Optional[dict[str, Any]] = None,
        authorization_ref: Optional[str] = None,
    ) -> bytes:
        """Generate full scan PDF report

        Args:
            scan_id: Internal scan identifier
            target: Target URL
            mode: Scan mode (quick/deep/etc)
            duration: Scan duration in seconds
            proxy: Proxy used (if any)
            vulns: list of vulnerabilities
            recon: Reconnaissance data (optional)
            authorization_ref: External authorization reference (defaults to scan_id if not provided)
        """
        # ========================================
        # v4.0.0 Phase 9: UNIFIED NORMALIZATION
        # ALL findings MUST pass through normalizer before report
        # ========================================
        normalized: dict[str, list[dict[str, Any]]] = {"confirmed": [], "potential": []}
        if isinstance(vulns, dict) and ("confirmed" in vulns or "potential" in vulns):
            normalized["confirmed"] = vulns.get("confirmed", [])
            normalized["potential"] = vulns.get("potential", [])
        else:
            vulns_list = []
            for v in vulns or []:
                if isinstance(v, dict):
                    vulns_list.append(v)
                elif hasattr(v, "__dict__"):
                    vulns_list.append(vars(v))
                else:
                    vulns_list.append({"payload": str(v)})
            if NORMALIZER_AVAILABLE:
                normalized = prepare_findings_for_report(vulns_list, mode=mode)
            else:
                normalized["confirmed"] = vulns_list

        html = self._build_scan_html(
            scan_id, target, mode, duration, proxy, normalized, recon, authorization_ref
        )
        return self._html_to_pdf(html)

    def _html_to_pdf(self, html: str) -> bytes:
        """Convert HTML to PDF"""
        if self._weasyprint:
            doc = self._weasyprint.HTML(string=html)
            return doc.write_pdf()
        else:
            # Fallback: return HTML as bytes (can be opened in browser)
            return html.encode("utf-8")

    def _build_recon_html(
        self, scan_id: str, target: str, profile: dict[str, Any]
    ) -> str:
        """Build reconnaissance report HTML"""
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        dns = profile.get("dns") or {}
        records = dns.get("records", {})
        ips = dns.get("ips") or []
        if not ips:
            ips = [
                rec.get("value", "") for rec in records.get("A", []) if rec.get("value")
            ]
            ips += [
                rec.get("value", "")
                for rec in records.get("AAAA", [])
                if rec.get("value")
            ]
        ns_records = dns.get("ns") or dns.get("nameservers") or []
        ns_display = ", ".join(ns_records) if ns_records else ""
        if not ns_display and dns:
            domain = dns.get("domain", "")
            if domain.endswith("appspot.com"):
                ns_display = "Google-managed (App Engine)"
            elif domain.endswith("cloudfront.net"):
                ns_display = "AWS CloudFront managed"
            else:
                ns_display = "Managed by upstream provider"
        mx_records = dns.get("mx")
        if not mx_records:
            mx_records = [
                rec.get("value", "")
                for rec in records.get("MX", [])
                if rec.get("value")
            ]

        dns_html = ""
        if dns:
            dns_html = f"""
            <div class="section">
                <h2>DNS Information</h2>
                <div class="grid">
                    <div class="grid-row">
                        <div class="grid-cell label">Domain</div>
                        <div class="grid-cell">{self._esc(dns.get('domain', 'N/A'))}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">IP Addresses</div>
                        <div class="grid-cell">{', '.join(ips) if ips else 'N/A'}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">NS Records</div>
                        <div class="grid-cell">{ns_display or 'Managed by upstream provider'}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">MX Records</div>
                        <div class="grid-cell">{', '.join(mx_records) if mx_records else 'N/A'}</div>
                    </div>
                </div>
            </div>
            """

        security_headers = profile.get("security_headers") or {}
        risk = profile.get("risk") or {}
        ssl = profile.get("ssl") or {}
        waf = profile.get("waf") or {}

        risk_level = (risk.get("risk_level") or "unknown").title()
        overall_score = risk.get("overall_score")
        header_gaps = []
        if security_headers and not security_headers.get("csp_present"):
            header_gaps.append("CSP missing")
        if security_headers and not security_headers.get("hsts_enabled"):
            header_gaps.append("HSTS missing")
        if security_headers and not security_headers.get("x_frame_options"):
            header_gaps.append("X-Frame-Options missing")
        header_summary = (
            ", ".join(header_gaps) if header_gaps else "Baseline headers present"
        )
        waf_conf = waf.get("confidence")
        if waf_conf is None:
            waf_conf = 0.0
        waf_summary = (
            "Not detected (passive)"
            if not waf.get("detected")
            else f"{waf.get('name', 'Detected')} ({waf_conf*100:.0f}% confidence)"
        )
        dns_summary = ns_display or "Managed by upstream provider"
        tls_summary = (
            f"{ssl.get('grade', 'N/A')} issued by {ssl.get('issuer', 'Unknown issuer')}"
            if ssl
            else "TLS data unavailable"
        )

        exec_html = f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="grid">
                <div class="grid-row">
                    <div class="grid-cell label">Risk Level</div>
                    <div class="grid-cell">{risk_level} ({overall_score if overall_score is not None else 'N/A'}/10)</div>
                </div>
                <div class="grid-row">
                    <div class="grid-cell label">DNS / Hosting</div>
                    <div class="grid-cell">{dns_summary}</div>
                </div>
                <div class="grid-row">
                    <div class="grid-cell label">TLS Posture</div>
                    <div class="grid-cell">{tls_summary}</div>
                </div>
                <div class="grid-row">
                    <div class="grid-cell label">Security Headers</div>
                    <div class="grid-cell">{header_summary}</div>
                </div>
                <div class="grid-row">
                    <div class="grid-cell label">WAF</div>
                    <div class="grid-cell">{waf_summary}</div>
                </div>
            </div>
        </div>
        """

        # Geolocation
        geo_html = ""
        if profile.get("geo"):
            geo = profile["geo"]
            geo_html = f"""
            <div class="section">
                <h2>Geolocation</h2>
                <div class="grid">
                    <div class="grid-row">
                        <div class="grid-cell label">Country</div>
                        <div class="grid-cell">{self._esc(geo.get('country', 'N/A'))}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">City</div>
                        <div class="grid-cell">{self._esc(geo.get('city', 'N/A'))}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">ISP</div>
                        <div class="grid-cell">{self._esc(geo.get('isp', 'N/A'))}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">ASN</div>
                        <div class="grid-cell">{self._esc(geo.get('asn', 'N/A'))}</div>
                    </div>
                </div>
            </div>
            """

        # SSL/TLS
        ssl_html = ""
        if profile.get("ssl"):
            ssl = profile["ssl"]
            ssl_html = f"""
            <div class="section">
                <h2>SSL/TLS Certificate</h2>
                <div class="grid">
                    <div class="grid-row">
                        <div class="grid-cell label">Issuer</div>
                        <div class="grid-cell">{self._esc(ssl.get('issuer', 'N/A'))}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Valid Until</div>
                        <div class="grid-cell">{self._esc(ssl.get('valid_until', 'N/A'))}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Protocol</div>
                        <div class="grid-cell">{self._esc(ssl.get('protocol', 'N/A'))}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Grade</div>
                        <div class="grid-cell">{self._esc(ssl.get('grade', 'N/A'))}</div>
                    </div>
                </div>
            </div>
            """

        # Technologies
        tech_html = ""
        if profile.get("technologies"):
            techs = profile["technologies"]
            tech_items = []
            for tech in techs:
                name = tech.get("name", "Unknown")
                version = tech.get("version", "")
                tech_items.append(f"{name} {version}".strip())

            tech_html = f"""
            <div class="section">
                <h2>Technologies Detected</h2>
                <p>{', '.join(tech_items) if tech_items else 'None detected'}</p>
            </div>
            """

        # Security Headers
        headers_html = ""
        if security_headers:
            sh = security_headers
            rows: list[str] = []

            def add_row(header: str, status: str, risk: str) -> None:
                rows.append(
                    f"<tr><td>{header}</td><td>{status}</td><td>{risk}</td></tr>"
                )

            add_row(
                "Content-Security-Policy",
                "Present" if sh.get("csp_present") else "Missing",
                "High" if not sh.get("csp_present") else "Low",
            )
            add_row(
                "X-Frame-Options",
                self._esc(sh.get("x_frame_options") or "Missing"),
                "Medium" if not sh.get("x_frame_options") else "Low",
            )
            xss_flag = sh.get("x_xss_protection", "")
            if xss_flag == "0":
                xss_status = "Disabled"
                xss_risk = "Low (legacy)"
            elif xss_flag:
                xss_status = self._esc(xss_flag)
                xss_risk = "Low"
            else:
                xss_status = "Missing"
                xss_risk = "Low (legacy)"
            add_row("X-XSS-Protection", xss_status, xss_risk)
            add_row(
                "Strict-Transport-Security",
                "Enabled" if sh.get("hsts_enabled") else "Missing",
                "Medium" if not sh.get("hsts_enabled") else "Low",
            )
            add_row(
                "Referrer-Policy",
                self._esc(sh.get("referrer_policy") or "Missing"),
                "Medium" if not sh.get("referrer_policy") else "Low",
            )
            add_row(
                "Permissions-Policy",
                self._esc(sh.get("permissions_policy") or "Missing"),
                "Medium" if not sh.get("permissions_policy") else "Low",
            )

            headers_html = f"""
            <div class="section">
                <h2>Security Headers</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Status</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
            """

        # WAF
        waf_html = ""
        if waf:
            detected = waf.get("detected", False)
            waf_name = waf.get("name") or (
                "Not detected" if not detected else "Unknown"
            )
            if detected:
                conf_value = waf.get("confidence") or 0.0
                posture = "Active" if conf_value >= 0.5 else "Passive"
                confidence = f"{conf_value * 100:.0f}% ({posture})"
            else:
                confidence = "Low (passive monitoring)"
            waf_html = f"""
            <div class="section">
                <h2>WAF Detection</h2>
                <div class="grid">
                    <div class="grid-row">
                        <div class="grid-cell label">Detected</div>
                        <div class="grid-cell">{self._esc(waf_name)}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Confidence</div>
                        <div class="grid-cell">{confidence}</div>
                    </div>
                </div>
            </div>
            """

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>{self.CSS}</style>
        </head>
        <body>
            <div class="header">
                {self._get_logo_html()}
                <div class="company">EasyProTech LLC | www.easypro.tech</div>
                <h1>BRS-XSS Reconnaissance Report</h1>
                <div class="subtitle">Target: {self._esc(target)} | Scan: {scan_id[:8]} | {now}</div>
            </div>
            
            {exec_html}
            {dns_html}
            {geo_html}
            {ssl_html}
            {tech_html}
            {headers_html}
            {waf_html}
            
            <div class="footer">
                <a href="https://github.com/EPTLLC/brs-xss" style="color: #f97316;"><b>BRS-XSS Scanner</b></a> | <a href="https://easypro.tech" style="color: #737373;">EasyProTech LLC</a><br>
                <span style="color: #ca8a04;">Authorized security testing only. Unauthorized use is illegal.</span>
            </div>
        </body>
        </html>
        """

    def _build_scan_html(
        self,
        scan_id: str,
        target: str,
        mode: str,
        duration: float,
        proxy: str,
        vulns: dict[str, list[dict[str, Any]]],
        recon: Optional[dict[str, Any]] = None,
        authorization_ref: Optional[str] = None,
    ) -> str:
        """Build full scan report HTML

        Args:
            scan_id: Internal scan identifier
            authorization_ref: External authorization reference (separate from scan_id)
        """
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        # Authorization Reference defaults to a generated value if not provided
        auth_ref = authorization_ref or f"AUTH-{scan_id[:8].upper()}"
        dur = (
            f"{int(duration//60)}m {int(duration%60)}s"
            if duration >= 60
            else f"{int(duration)}s"
        )

        # Helper to get severity - works with both dicts and objects
        def get_sev(v):
            if isinstance(v, dict):
                return v.get("severity", "")
            return getattr(v, "severity", "")

        confirmed = vulns.get("confirmed", [])
        potential = vulns.get("potential", [])

        # Count by severity (confirmed only)
        critical = sum(1 for v in confirmed if get_sev(v) == "critical")
        high = sum(1 for v in confirmed if get_sev(v) == "high")
        medium = sum(1 for v in confirmed if get_sev(v) == "medium")
        low = sum(1 for v in confirmed if get_sev(v) == "low")
        total = len(confirmed)

        # Stats section
        stats_html = f"""
        <div class="section">
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" style="color: {self.COLORS['critical']}">{critical}</div>
                    <div class="stat-label">CRITICAL</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: {self.COLORS['high']}">{high}</div>
                    <div class="stat-label">HIGH</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: {self.COLORS['medium']}">{medium}</div>
                    <div class="stat-label">MEDIUM</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: {self.COLORS['low']}">{low}</div>
                    <div class="stat-label">LOW</div>
                </div>
            </div>
        </div>
        """
        # Executive summary
        if critical:
            risk_rating = "Critical"
        elif high:
            risk_rating = "High"
        elif medium:
            risk_rating = "Medium"
        else:
            risk_rating = "Low"
        summary_points = []
        if critical:
            summary_points.append(
                f"{critical} DOM-based chain(s) auto-executed (location.search → DOM)."
            )
        if high:
            summary_points.append(f"{high} reflected finding(s) confirmed.")
        if medium:
            summary_points.append(f"{medium} medium finding(s) detected.")
        if potential:
            summary_points.append(
                f"{len(potential)} heuristic finding(s) require manual validation."
            )
        if not summary_points:
            summary_points.append("No XSS vulnerabilities detected during this run.")
        summary_list = "".join(f"<li>{self._esc(item)}</li>" for item in summary_points)
        exec_html = f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="grid">
                <div class="grid-row">
                    <div class="grid-cell label">Overall Risk</div>
                    <div class="grid-cell">{risk_rating}</div>
                </div>
                <div class="grid-row">
                    <div class="grid-cell label">Confirmed / Heuristic</div>
                    <div class="grid-cell">{total} / {len(potential)}</div>
                </div>
            </div>
            <ul>
                {summary_list}
            </ul>
        </div>
        """

        # Vulnerabilities section (Finding vs Evidence pattern) - deduplicated
        vulns_html = ""
        if confirmed:
            vuln_items = ""

            # v4.0.0 Phase 9: Normalization now happens in generate_scan_report()
            # No need to apply rules here - findings are already normalized

            for v in confirmed:
                # Support both dict and object
                if isinstance(v, dict):
                    sev = v.get("severity", "medium")
                    url = v.get("url", "")
                    param = v.get("parameter", "")
                    payload = v.get("payload", "")
                    ctx = v.get("context", v.get("context_type", ""))
                    # v4.0.0: Check vulnerability_type first (from scanner), then xss_type
                    xss_type = v.get("vulnerability_type", v.get("xss_type", ""))
                    sink = v.get("sink", "")
                    source = v.get("source", "")
                    confidence = v.get("confidence", 0.8)
                    cvss_score = v.get("cvss_score")
                    evidence_count = v.get("evidence_count", 1)
                    v.get("evidence_payloads", [])
                    v.get("early_stopped", False)
                else:
                    sev = getattr(v, "severity", "medium")
                    url = getattr(v, "url", "")
                    param = getattr(v, "parameter", "")
                    payload = getattr(v, "payload", "")
                    ctx = getattr(v, "context", getattr(v, "context_type", ""))
                    # v4.0.0: Check vulnerability_type first (from scanner), then xss_type
                    xss_type = getattr(
                        v, "vulnerability_type", getattr(v, "xss_type", "")
                    )
                    sink = getattr(v, "sink", "")
                    source = getattr(v, "source", "")
                    confidence = getattr(v, "confidence", 0.8)
                    cvss_score = getattr(v, "cvss_score", None)
                    evidence_count = getattr(v, "evidence_count", 1)
                    getattr(v, "evidence_payloads", [])
                    getattr(v, "early_stopped", False)

                # ========================================
                # v4.0.0: CRITICAL - XSS Type Determination
                # ========================================
                # Rule 1: If parameter is unknown/empty, CANNOT be Reflected
                # Rule 2: If payload contains DOM markers, it's DOM XSS
                # Rule 3: Use context clues as fallback

                # Check if already classified as DOM
                is_dom_type = xss_type and "DOM" in xss_type

                # Check if should be DOM but was misclassified
                should_be_dom = False

                # Rule 1: parameter=unknown -> NOT Reflected
                if param in ("unknown", "", None):
                    should_be_dom = True

                # Rule 2: DOM markers in payload
                dom_markers = ["DOM_XSS", "fragment", "postmessage", "storage"]
                payload_lower = payload.lower()
                if any(marker in payload_lower for marker in dom_markers):
                    should_be_dom = True

                # Rule 3: Context clues
                ctx_str = str(ctx) if ctx else ""
                if (
                    "DOM" in ctx_str
                    or "dom" in ctx_str.lower()
                    or sink
                    or "->" in ctx_str
                ):
                    should_be_dom = True

                # Apply DOM classification if needed
                if should_be_dom and not is_dom_type:
                    # Determine DOM subtype from payload
                    if "<script" in payload_lower:
                        xss_type = "DOM XSS (Script Injection)"
                    elif any(
                        h in payload_lower for h in ["onerror", "onload", "onmouseover"]
                    ):
                        xss_type = "DOM XSS (Event Handler)"
                    elif "innerhtml" in payload_lower or sink == "innerHTML":
                        xss_type = "DOM XSS (innerHTML)"
                    else:
                        xss_type = "DOM-Based XSS"

                # Fallback if still empty
                if not xss_type:
                    if param and param not in ("unknown", ""):
                        xss_type = "Reflected XSS"
                    else:
                        xss_type = "DOM-Based XSS"

                # ========================================
                # v4.0.0: Confidence floor for deterministic payloads
                # ========================================
                # <script> tags should have 95%+ confidence
                if "<script" in payload_lower and confidence < 0.95:
                    confidence = 0.95

                # Extract sink from stored metadata or context (only if not already extracted)
                if isinstance(v, dict):
                    # For dicts, sink should already be set from dict
                    if not sink and "->" in ctx_str:
                        sink = ctx_str.split("->")[-1].strip()
                else:
                    # For objects, check stored attributes
                    sink = getattr(v, "_sink", None) or sink
                    if not sink and "->" in ctx_str:
                        sink = ctx_str.split("->")[-1].strip()

                # Extract source from stored metadata or context (only if not already extracted)
                if isinstance(v, dict):
                    # For dicts, source should already be set from dict
                    if not source and "->" in ctx_str:
                        source = ctx_str.split("->")[0].strip()
                else:
                    # For objects, check stored attributes
                    source = getattr(v, "_source", None) or source
                    if not source and "->" in ctx_str:
                        source = ctx_str.split("->")[0].strip()

                # ========================================
                # v4.0.0: Enhanced context display
                # ========================================
                # For <script> payloads, show more specific context
                if "<script" in payload_lower and ctx == "html":
                    ctx = "html > script"

                # Sink API information
                sink_info = ""
                if sink:
                    sink_info = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Sink API</div>
                            <div class="grid-cell"><code>Element.{sink}</code></div>
                        </div>
                    """

                impact_scope = v.get("impact_scope")
                impact_info = ""
                if impact_scope:
                    impact_info = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Impact Scope</div>
                            <div class="grid-cell">{self._esc(impact_scope)}</div>
                        </div>
                    """

                # Confidence and Validation Level
                confidence_level = "auto-detected"
                if confidence >= 0.95:
                    confidence_level = "DOM confirmed"
                elif confidence >= 0.8:
                    confidence_level = "high confidence"

                confidence_info = f"""
                    <div class="grid-row">
                        <div class="grid-cell label">Confidence</div>
                        <div class="grid-cell">{int(confidence * 100)}% ({confidence_level})</div>
                    </div>
                """

                # CVSS Score if available
                cvss_info = ""
                if cvss_score:
                    cvss_info = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">CVSS Score</div>
                            <div class="grid-cell">{cvss_score:.1f}/10.0</div>
                        </div>
                    """

                # Evidence info
                evidence_info = ""
                if evidence_count > 1:
                    evidence_info = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Evidence</div>
                            <div class="grid-cell">{evidence_count} confirmed payloads</div>
                        </div>
                    """

                execution_info = ""
                exec_proof = v.get("execution_proof")
                if exec_proof:
                    execution_info = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Execution Proof</div>
                            <div class="grid-cell">{self._esc(exec_proof)}</div>
                        </div>
                    """

                exploit_info = ""
                exploit = v.get("exploitability") or {}
                if exploit:
                    exploit_info = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Exploitability</div>
                            <div class="grid-cell">
                                User interaction: {self._esc(exploit.get('user_interaction', 'Not evaluated'))}<br>
                                Persistence: {self._esc(exploit.get('persistence', 'Not evaluated'))}<br>
                                Authentication: {self._esc(exploit.get('authentication', 'Not evaluated'))}
                            </div>
                        </div>
                    """

                # Payload class and trigger
                payload_info = ""
                if "onerror" in payload.lower() or "onload" in payload.lower():
                    trigger = (
                        "img.onerror" if "onerror" in payload.lower() else "img.onload"
                    )
                    payload_info = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Payload Class</div>
                            <div class="grid-cell">HTML Attribute Injection | Trigger: {trigger}</div>
                        </div>
                    """

                status_badge = ""
                if isinstance(v, dict) and v.get("status") == "potential":
                    status_badge = '<span style="font-size:8pt;color:#facc15;margin-left:8pt;">POTENTIAL</span>'

                vuln_items += f"""
                <div class="vuln {sev}">
                    <div class="vuln-header">
                        <span class="severity {sev}">{sev.upper()}</span>
                        <span style="font-size: 9pt; color: #737373;">{xss_type}</span>
                        {status_badge}
                    </div>
                    <div class="grid">
                        <div class="grid-row">
                            <div class="grid-cell label">URL</div>
                            <div class="grid-cell"><code>{self._esc(url[:100])}</code></div>
                        </div>
                        <div class="grid-row">
                            <div class="grid-cell label">Parameter</div>
                            <div class="grid-cell"><code>{self._esc(param)}</code></div>
                        </div>
                        <div class="grid-row">
                            <div class="grid-cell label">Context</div>
                            <div class="grid-cell">{self._esc(ctx_str)}</div>
                        </div>
                        {sink_info}
                        {impact_info}
                        {execution_info}
                        {exploit_info}
                        <div class="grid-row">
                            <div class="grid-cell label">Primary Payload</div>
                            <div class="grid-cell"><code>{self._esc(payload[:80])}</code></div>
                        </div>
                        {payload_info}
                        {confidence_info}
                        {cvss_info}
                        {evidence_info}
                    </div>
                </div>
                """

            # Title: Findings (not Vulnerabilities)
            vulns_html = f"""
            <div class="section">
                <h2>Findings ({total})</h2>
                {vuln_items}
            </div>
            """
        else:
            vulns_html = """
            <div class="section">
                <h2>Vulnerabilities</h2>
                <p style="color: #16a34a; text-align: center; padding: 20px;">
                    No XSS vulnerabilities detected
                </p>
            </div>
            """

        potential_html = ""
        if potential:
            potential_cards = ""
            for pv in potential:
                ctx = pv.get("context", pv.get("context_type", "unknown"))
                impact_scope = pv.get("impact_scope")
                exec_proof = pv.get("execution_proof")
                exploit = pv.get("exploitability") or {}
                impact_html = ""
                if impact_scope:
                    impact_html = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Impact Scope</div>
                            <div class="grid-cell">{self._esc(impact_scope)}</div>
                        </div>
                    """
                exec_html_row = ""
                if exec_proof:
                    exec_html_row = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Execution Proof</div>
                            <div class="grid-cell">{self._esc(exec_proof)}</div>
                        </div>
                    """
                exploit_html = ""
                if exploit:
                    exploit_html = f"""
                        <div class="grid-row">
                            <div class="grid-cell label">Exploitability</div>
                            <div class="grid-cell">
                                User interaction: {self._esc(exploit.get('user_interaction', 'Not evaluated'))}<br>
                                Persistence: {self._esc(exploit.get('persistence', 'Not evaluated'))}<br>
                                Authentication: {self._esc(exploit.get('authentication', 'Not evaluated'))}
                            </div>
                        </div>
                    """
                potential_cards += f"""
                <div class="vuln low">
                    <div class="vuln-header">
                        <span class="severity low">POTENTIAL</span>
                        <span style="font-size: 9pt; color: #737373;">Heuristic</span>
                    </div>
                    <div class="grid">
                        <div class="grid-row">
                            <div class="grid-cell label">URL</div>
                            <div class="grid-cell"><code>{self._esc(pv.get('url', 'unknown'))}</code></div>
                        </div>
                        <div class="grid-row">
                            <div class="grid-cell label">Parameter</div>
                            <div class="grid-cell"><code>{self._esc(pv.get('parameter', 'unknown'))}</code></div>
                        </div>
                        <div class="grid-row">
                            <div class="grid-cell label">Context</div>
                            <div class="grid-cell">{self._esc(ctx)}</div>
                        </div>
                        {impact_html}
                        {exec_html_row}
                        <div class="grid-row">
                            <div class="grid-cell label">Payload</div>
                            <div class="grid-cell"><code>{self._esc(pv.get('payload', '')[:120])}</code></div>
                        </div>
                        <div class="grid-row">
                            <div class="grid-cell label">Confidence</div>
                            <div class="grid-cell">{int(float(pv.get('confidence', 0.3))*100)}% (manual confirmation required)</div>
                        </div>
                        {exploit_html}
                    </div>
                </div>
                """
            potential_html = f"""
            <div class="section">
                <h2>Potential Issues (Heuristic)</h2>
                {potential_cards}
            </div>
            """

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>{self.CSS}</style>
        </head>
        <body>
            <div class="header">
                {self._get_logo_html()}
                <div class="company">EasyProTech LLC | www.easypro.tech</div>
                <h1>BRS-XSS Scan Report</h1>
                <div class="subtitle">Target: {self._esc(target)} | Mode: {mode} | {now}</div>
            </div>
            
            {exec_html}
            <div class="section">
                <h2>Scan Summary</h2>
                <div class="grid">
                    <div class="grid-row">
                        <div class="grid-cell label">Scan ID</div>
                        <div class="grid-cell">{scan_id}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Target</div>
                        <div class="grid-cell"><code>{self._esc(target)}</code></div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Mode</div>
                        <div class="grid-cell">{mode}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Duration</div>
                        <div class="grid-cell">{dur}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Via</div>
                        <div class="grid-cell">{self._esc(proxy) if proxy else 'Direct IP'}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Confirmed Findings</div>
                        <div class="grid-cell">{total}</div>
                    </div>
                    <div class="grid-row">
                        <div class="grid-cell label">Heuristic Findings</div>
                        <div class="grid-cell">{len(potential)}</div>
                    </div>
                </div>
            </div>
            
            {stats_html}
            {vulns_html}
            {potential_html}
            
            <div class="footer">
                <a href="https://github.com/EPTLLC/brs-xss" style="color: #f97316;"><b>BRS-XSS Scanner</b></a> | <a href="https://easypro.tech" style="color: #737373;">EasyProTech LLC</a><br>
                <span style="color: #ca8a04;">Authorized security testing only. Unauthorized use is illegal.</span><br>
                <span style="color: #525252; font-size: 7pt;">Scan ID: {scan_id} | Test Mode: Lab Environment | Authorization Reference: {auth_ref}</span>
            </div>
        </body>
        </html>
        """

    def _get_logo_html(self) -> str:
        """Return logo HTML if available"""
        if self._logo_b64:
            return f'<img src="data:image/jpeg;base64,{self._logo_b64}" class="logo" alt="EasyProTech">'
        return ""

    def _esc(self, text: str) -> str:
        if not text:
            return ""
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
