#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 02:32:00 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import asyncio
from typing import Optional
from urllib.parse import urlparse, urljoin

import typer
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from brsxss import __version__
from brsxss.core.scanner import XSSScanner
from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics
from brsxss.utils.logger import Logger
from brsxss.crawler.data_models import DiscoveredParameter

console = Console()


async def simple_scan(
    target: str,
    threads: int = 10,
    timeout: int = 15,
    output: Optional[str] = None,
    deep: bool = False,
    verbose: bool = False,
    ml_mode: bool = False,
    blind_xss_webhook: Optional[str] = None,
    no_ssl_verify: bool = False,
    safe_mode: bool = True,
    pool_cap: int = 10000,
    max_payloads: int = 500,
):
    """Scan target for XSS vulnerabilities - specify domain or IP only"""
    
    # Configure logging based on verbosity
    Logger.configure_logging(verbose=verbose)

    logger = Logger("cli.simple_scan")
    
    console.print(f"[bold green]BRS-XSS v{__version__}[/bold green]")
    console.print(f"Target: {target}")
    
    if verbose:
        console.print("[dim]Verbose mode enabled - detailed parameter analysis[/dim]")
    if ml_mode:
        console.print("[dim]ML mode enabled - vulnerability classification[/dim]")
    
    # Scanner will be created with progress callback during scanning
    
    if blind_xss_webhook:
        console.print(f"Blind XSS webhook enabled: {blind_xss_webhook}")
    
    try:
        # Auto-detect protocol and build URLs
        # Force HTTP for internal IPs when SSL verification is disabled
        force_http = no_ssl_verify and (
            target.startswith('192.168.') or target.startswith('10.') or target.startswith('172.') or
            target.startswith('127.') or 'localhost' in target
        )
        scan_targets = _build_scan_targets(target, force_http)
        
        console.print(f"Auto-detected {len(scan_targets)} targets to scan")
        
        all_vulnerabilities = []
        
        with Progress() as progress:
            # Create main task for URLs
            url_task = progress.add_task("Scanning targets...", total=len(scan_targets))
            # Create detailed task for payloads
            payload_task = progress.add_task("Testing payloads...", total=100)
            
            def update_payload_progress(current: int, total: int):
                """Update payload progress bar"""
                if total > 0:
                    percentage = min(100, (current * 100) // total)
                    progress.update(payload_task, completed=percentage, total=100,
                                  description=f"Testing payload {current}/{total}")
            
            # Create a single reusable HTTP client
            from brsxss.core.http_client import HTTPClient
            http_client = HTTPClient(timeout=timeout, verify_ssl=not no_ssl_verify)
            
            try:
                for url in scan_targets:
                    progress.update(url_task, description=f"Scanning {url}")
                    progress.update(payload_task, completed=0, description="Discovering parameters...")
                    
                    try:
                        # Auto-discover parameters (entry points)
                        discovered_params = await _discover_parameters(url, deep, http_client)
                        
                        if discovered_params:
                            progress.print(f"Found {len(discovered_params)} entry points in {url}")
                            
                            # Create scanner with progress callback
                            scanner_with_progress = XSSScanner(
                                timeout=timeout, 
                                max_concurrent=threads, 
                                verify_ssl=not no_ssl_verify, 
                                blind_xss_webhook=blind_xss_webhook,
                                progress_callback=update_payload_progress,
                                http_client=http_client  # Reuse client
                            )
                            
                            # Scan each discovered entry point
                            for entry_point in discovered_params:
                                vulns = await scanner_with_progress.scan_url(
                                    entry_point.url, 
                                    entry_point.method,
                                    entry_point.params
                                )
                                all_vulnerabilities.extend(vulns)
                            
                        progress.advance(url_task)
                        progress.update(payload_task, completed=100, description="URL scan completed")
                        
                    except Exception as e:
                        logger.warning(f"Error scanning {url}: {e}")
                        progress.advance(url_task)
            
            finally:
                # Ensure the shared HTTP client is closed
                await http_client.close()

        # Display results in a rich table
        console.print("\n[bold]Scan Summary[/bold]")
        
        if all_vulnerabilities:
            def _sev_str(value):
                try:
                    # Enum with value
                    v = getattr(value, 'value', None)
                    if isinstance(v, str):
                        return v.lower()
                    # Enum name
                    n = getattr(value, 'name', None)
                    if isinstance(n, str):
                        return n.lower()
                except Exception:
                    pass
                if isinstance(value, str):
                    return value.lower()
                return 'low'

            table = Table(title="Vulnerabilities Found", show_header=True, header_style="bold magenta")
            table.add_column("Severity", style="dim", width=12)
            table.add_column("URL", style="cyan")
            table.add_column("Method", style="green")
            table.add_column("Parameter", style="yellow")
            table.add_column("Payload Snippet", style="white")

            severity_colors = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "cyan",
                "info": "green"
            }

            # Sort vulnerabilities by severity (high to low)
            severities = ["critical", "high", "medium", "low", "info"]
            sorted_vulns = sorted(
                all_vulnerabilities,
                key=lambda v: severities.index(_sev_str(v.get('severity', 'low'))) if _sev_str(v.get('severity', 'low')) in severities else 99
            )

            for vuln in sorted_vulns:
                severity = _sev_str(vuln.get('severity', 'low'))
                color = severity_colors.get(severity, "white")
                
                payload = vuln.get('payload', '')
                payload_snippet = (payload[:40] + '...') if len(payload) > 40 else payload

                table.add_row(
                    f"[{color}]{severity.upper()}[/{color}]",
                    vuln.get('url', ''),
                    vuln.get('http_method', 'GET'),
                    vuln.get('parameter', ''),
                    payload_snippet
                )
            
            console.print(table)
        else:
            console.print("[green]✔ No vulnerabilities found - target appears secure.[/green]")
        
        # Save report
        if not output:
            # Default output path (sanitized + ensured directories)
            import os
            from brsxss.utils.paths import sanitize_filename, ensure_dir
            timestamp = int(__import__('time').time())
            clean_target = sanitize_filename(target, max_len=50)
            filename = f"scan_report_{clean_target}_{timestamp}.json"
            results_dir = os.path.abspath("results/json")
            ensure_dir(results_dir)
            output = os.path.join(results_dir, filename)
        
        _save_simple_report(all_vulnerabilities, scan_targets, output)
        console.print(f"Report saved: {output}")

        # Generate multi-format report (HTML + JSON)
        try:
            # Convert to VulnerabilityData
            vuln_items = []
            for idx, v in enumerate(all_vulnerabilities, 1):
                severity = v.get('severity')
                if hasattr(severity, 'value'):
                    severity = severity.value  # type: ignore[union-attr]
                elif not isinstance(severity, str):
                    severity = 'low'
                vuln_items.append(
                    VulnerabilityData(
                        id=f"xss_{idx}",
                        title=f"XSS in parameter {v.get('parameter','')}",
                        description=f"Possible XSS detected for parameter {v.get('parameter','')}.",
                        severity=severity,
                        confidence=float(v.get('confidence', 0.5)),
                        url=v.get('url',''),
                        parameter=v.get('parameter',''),
                        payload=v.get('payload',''),
                    )
                )

            # Scan statistics
            stats = ScanStatistics(
                total_urls_tested=len(scan_targets),
                total_parameters_tested=sum(len((await _discover_parameters(u, False, None))) for u in scan_targets if isinstance(u,str)) if False else 0,
                total_payloads_tested=0,
                total_requests_sent=0,
                scan_duration=0.0,
                vulnerabilities_found=len(vuln_items),
            )

            # Configure report
            report_config = ReportConfig(
                title=f"BRS-XSS Scan Report - {scan_targets[0] if scan_targets else target}",
                output_dir="results",
                filename_template="brsxss_report_{timestamp}",
                formats=[ReportFormat.HTML, ReportFormat.JSON],
                include_recommendations=True,
                include_methodology=True,
            )
            generator = ReportGenerator(report_config)
            # Load config for report generation
            from brsxss.core.config_manager import ConfigManager
            config_mgr = ConfigManager()
            
            policy = {
                'min_vulnerability_score': config_mgr.get('scanner.min_vulnerability_score', 2.0),
                'severity_bands': {
                    'critical': '>= 9.0', 'high': '>=7.0', 'medium': '>=4.0', 'low': '>=1.0', 'info': '>0'
                }
            }
            generated = generator.generate_report(vuln_items, stats, target_info={"url": target, "policy": policy})

            # Move reports to structured directories
            import os
            os.makedirs("results/html", exist_ok=True)
            os.makedirs("results/json", exist_ok=True)
            for fmt, path in generated.items():
                try:
                    if path.endswith('.html'):
                        new_path = os.path.join("results/html", os.path.basename(path))
                    elif path.endswith('.json'):
                        new_path = os.path.join("results/json", os.path.basename(path))
                    else:
                        new_path = path
                    if new_path != path:
                        os.replace(path, new_path)
                        path = new_path
                except Exception as move_err:
                    logger.debug(f"Report move error: {move_err}")
                console.print(f"Report generated: {path}")
        except Exception as e:
            logger.debug(f"Failed to generate report: {e}")
    
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise typer.Exit(1)
    
    finally:
        # Clean up HTTP sessions
        try:
            # Give time for pending requests to complete
            await asyncio.sleep(0.5)
            # Note: Individual scanners are cleaned up in the loop above
            # Additional delay to ensure SSL cleanup
            await asyncio.sleep(0.5)
        except Exception as e:
            logger.debug(f"Error in cleanup: {e}")


def _build_scan_targets(target: str, force_http: bool = False) -> list:
    """Build list of URLs to scan from target domain/IP"""
    
    # Clean target
    target = target.strip()
    
    # Check if target is already a full URL with path/query
    if target.startswith(('http://', 'https://')):
        # User provided full URL - use it directly
        return [target]
    elif '/' in target or '?' in target:
        # User provided domain with path/query - add protocols
        # If non-SSL port is explicitly specified, avoid adding https
        non_ssl_port = (":" in target) and not (":443" in target or ":8443" in target)
        if force_http or non_ssl_port:
            return [f"http://{target}"]
        else:
            return [f"http://{target}", f"https://{target}"]
    
    # User provided only domain/IP - generate common endpoints
    target = target.lower()
    
    # Build target URLs
    targets = []
    
    # Smart protocol selection
    if force_http:
        # Force HTTP only for internal IPs or when SSL issues
        base_urls = [f"http://{target}"]
    else:
        # Try both HTTP and HTTPS for external domains
        base_urls = [f"http://{target}", f"https://{target}"]
    
    # Common paths to test
    common_paths = [
        "/",
        "/index.php",
        "/search.php", 
        "/login.php",
        "/contact.php",
        "/search",
        "/api/search",
        "/search?q=test",
        "/index.php?page=test",
        "/search.php?search=test",
        "/contact.php?name=test&email=test"
    ]
    
    for base_url in base_urls:
        for path in common_paths:
            targets.append(urljoin(base_url, path))
    
    return targets


async def _discover_parameters(url: str, deep_scan: bool = False, http_client=None) -> list[DiscoveredParameter]:
    """Auto-discover parameters in URL and forms, returning structured entry points."""
    
    entry_points = []
    
    # 1. Extract parameters from the initial URL itself (GET request)
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    
    if url_params:
        # Create an entry point for GET parameters in the URL
        # Keep the full URL with query string - scanner needs it
        entry_points.append(
            DiscoveredParameter(
                url=url,
                method="GET",
                params={param: values[0] if values else "test" for param, values in url_params.items()}
            )
        )

    # 2. If deep scan, crawl and extract forms
    if deep_scan and http_client:
        try:
            from brsxss.crawler.engine import CrawlerEngine, CrawlConfig
            from brsxss.crawler.form_extractor import FormExtractor
            
            config = CrawlConfig(
                max_depth=2, 
                max_urls=20, 
                max_concurrent=5, # Increased concurrency
                timeout=15,
                extract_forms=True,
                extract_links=True
            )
            crawler = CrawlerEngine(config, http_client)
            crawl_results = await crawler.crawl(url)
            
            form_extractor = FormExtractor()
            
            for result in crawl_results:
                if result.status_code == 200 and result.content:
                    forms = form_extractor.extract_forms(result.content, result.url)
                    
                    for form in forms:
                        # Create an entry point for each discovered form
                        form_params = {}
                        for field in form.testable_fields:
                            if field.field_type.name == 'PASSWORD':
                                form_params[field.name] = "password123"
                            elif field.field_type.name == 'EMAIL':
                                form_params[field.name] = "test@example.com"
                            else:
                                form_params[field.name] = "test"
                        
                        entry_points.append(
                            DiscoveredParameter(
                                url=form.action,
                                method=form.method.upper(),
                                params=form_params
                            )
                        )

        except Exception as e:
            logger = Logger("cli.simple_scan._discover_parameters")
            logger.error(f"Deep discovery failed: {e}")
            # Fallback to basic regex on the initial page if deep scan fails
            try:
                response = await http_client.get(url)
                if response.status_code == 200:
                    import re
                    form_inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', response.text, re.I)
                    if form_inputs:
                        entry_points.append(
                            DiscoveredParameter(
                                url=url,
                                method="GET", # Assume GET as a fallback
                                params={name: "test" for name in form_inputs}
                            )
                        )
            except Exception:
                pass # Ignore fallback errors
    
    # Remove duplicate entry points
    unique_entry_points = []
    seen = set()
    for ep in entry_points:
        # Create a unique key for each entry point
        key = (ep.url, ep.method, tuple(sorted(ep.params.keys())))
        if key not in seen:
            unique_entry_points.append(ep)
            seen.add(key)
            
    return unique_entry_points


def _save_simple_report(vulnerabilities: list, targets: list, output_path: str):
    """Save simple scan report"""
    
    import json
    from datetime import datetime
    from enum import Enum
    
    # Custom JSON encoder for Enum types
    class CustomJSONEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Enum):
                return obj.value
            return super().default(obj)
    
    # Convert vulnerabilities to serializable format recursively
    def make_serializable(obj):
        from dataclasses import is_dataclass, asdict
        
        if isinstance(obj, Enum):
            return obj.value
        elif is_dataclass(obj):
            return {k: make_serializable(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [make_serializable(item) for item in obj]
        else:
            return obj
    
    serializable_vulns = [make_serializable(vuln) for vuln in vulnerabilities]
    
    report = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "scanner": f"BRS-XSS Simple Scanner v{__version__}",
            "targets_scanned": len(targets),
            "vulnerabilities_found": len(serializable_vulns)
        },
        "targets": targets,
        "vulnerabilities": serializable_vulns
    }
    
    # Determine format by extension with atomic write
    from brsxss.utils.paths import atomic_write
    content = json.dumps(report, indent=2, cls=CustomJSONEncoder)
    if output_path.endswith('.json'):
        atomic_write(output_path, content)
    else:
        atomic_write(output_path + '.json', content)


def simple_scan_wrapper(
    target: str,
    threads: int = 10,
    timeout: int = 15,
    output: Optional[str] = None,
    deep: bool = False,
    verbose: bool = False,
    ml_mode: bool = False,
    blind_xss_webhook: Optional[str] = None,
    no_ssl_verify: bool = False,
    safe_mode: bool = True,
    pool_cap: int = 10000,
    max_payloads: int = 500,
):
    """Wrapper to run async scan function"""
    return asyncio.run(simple_scan(target, threads, timeout, output, deep, verbose, ml_mode, blind_xss_webhook, no_ssl_verify, safe_mode, pool_cap, max_payloads))

# Create typer app for this command
app = typer.Typer()
app.command()(simple_scan_wrapper)