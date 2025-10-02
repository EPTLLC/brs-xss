#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import asyncio
from typing import Optional
from urllib.parse import urlparse, urljoin

import typer
from rich.console import Console
from rich.progress import Progress

from brsxss import __version__
from brsxss.core.scanner import XSSScanner
from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig, ReportFormat
from brsxss.report.data_models import VulnerabilityData, ScanStatistics
from brsxss.utils.logger import Logger

console = Console()


async def simple_scan(
    target: str = typer.Argument(
        ...,
        help="Domain or IP address to scan (e.g. example.com, 192.168.1.1)",
        metavar="TARGET"
    ),
    threads: int = typer.Option(
        10,
        "--threads", "-t", 
        help="Concurrency (parallel requests)",
        min=1,
        max=50
    ),
    timeout: int = typer.Option(
        15,
        "--timeout",
        help="Request timeout in seconds",
        min=5,
        max=120
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path for report (defaults to results/json/)"
    ),
    deep: bool = typer.Option(True, "--deep/--no-deep", help="Enable deep scanning (crawling + forms)"),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output with detailed parameter analysis"
    ),
    ml_mode: bool = typer.Option(True, "--ml-mode/--no-ml-mode", help="Enable ML-based vulnerability classification"),
    blind_xss_webhook: Optional[str] = typer.Option(
        None,
        "--blind-xss",
        help="Webhook URL for blind XSS detection"
    ),
    no_ssl_verify: bool = typer.Option(False, "--no-ssl-verify", help="Disable SSL certificate verification (useful for internal/self-signed certs)"),
    safe_mode: bool = typer.Option(True, "--safe-mode/--no-safe-mode", help="Enable safe mode for production scanning"),
    pool_cap: int = typer.Option(10000, "--pool-cap", help="Maximum payload pool size", min=100, max=200000),
    max_payloads: int = typer.Option(500, "--max-payloads", help="Maximum payloads per context", min=1, max=10000),
):
    """Scan target for XSS vulnerabilities - specify domain or IP only"""
    
    logger = Logger("cli.simple_scan")
    
    console.print(f"[bold green]BRS-XSS v{__version__}[/bold green] - Serious XSS Scanner")
    console.print(f"Target: {target}")
    
    if verbose:
        console.print("[dim]Verbose mode enabled - detailed parameter analysis[/dim]")
    if ml_mode:
        console.print("[dim]ML mode enabled - advanced vulnerability classification[/dim]")
    
    # Scanner will be created with progress callback during scanning
    
    if blind_xss_webhook:
        console.print(f"Blind XSS webhook enabled: {blind_xss_webhook}")
    
    try:
        # Auto-detect protocol and build URLs
        # Force HTTP for internal IPs when SSL verification is disabled
        force_http = no_ssl_verify and (target.startswith('192.168.') or target.startswith('10.') or target.startswith('172.') or 'localhost' in target)
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
            
            for url in scan_targets:
                progress.update(url_task, description=f"Scanning {url}")
                progress.update(payload_task, completed=0, description="Discovering parameters...")
                
                try:
                    # Create temporary HTTP client for parameter discovery
                    from brsxss.core.http_client import HTTPClient
                    temp_client = HTTPClient(timeout=timeout, verify_ssl=not no_ssl_verify)
                    
                    # Auto-discover parameters
                    parameters = await _discover_parameters(url, deep, temp_client)
                    
                    if parameters:
                        console.print(f"Found {len(parameters)} parameters in {url}")
                        
                        # Create scanner with progress callback
                        scanner_with_progress = XSSScanner(
                            timeout=timeout, 
                            max_concurrent=threads, 
                            verify_ssl=not no_ssl_verify, 
                            blind_xss_webhook=blind_xss_webhook,
                            progress_callback=update_payload_progress
                        )
                        
                        # Scan this URL with its parameters
                        vulns = await scanner_with_progress.scan_url(url, parameters)
                        all_vulnerabilities.extend(vulns)
                        
                        # Cleanup
                        await scanner_with_progress.close()
                    
                    # Cleanup temporary client
                    await temp_client.close()
                    
                    progress.advance(url_task)
                    progress.update(payload_task, completed=100, description="URL scan completed")
                    
                except Exception as e:
                    logger.warning(f"Error scanning {url}: {e}")
                    progress.advance(url_task)
        
        # Display results
        console.print(f"\nScan completed: {len(all_vulnerabilities)} vulnerabilities found")
        
        if all_vulnerabilities:
            console.print("[red]VULNERABILITIES FOUND:[/red]")
            for i, vuln in enumerate(all_vulnerabilities, 1):
                console.print(f"  {i}. {vuln.get('url')} - {vuln.get('parameter')}")
        else:
            console.print("[green]No vulnerabilities found - target appears secure[/green]")
        
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

        # Generate professional multi-format report (HTML + JSON)
        try:
            # Convert to VulnerabilityData
            vuln_items = []
            for idx, v in enumerate(all_vulnerabilities, 1):
                severity = v.get('severity')
                if hasattr(severity, 'value'):
                    severity = severity.value
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
                console.print(f"Professional report generated: {path}")
        except Exception as e:
            logger.debug(f"Failed to generate professional report: {e}")
    
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
        if force_http:
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


async def _discover_parameters(url: str, deep_scan: bool = False, http_client=None) -> dict:
    """Auto-discover parameters in URL and forms with advanced extraction"""
    
    parameters = {}
    
    # Extract URL parameters
    from urllib.parse import parse_qs
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    
    for param, values in url_params.items():
        parameters[param] = values[0] if values else "test"
    
    # If deep scan enabled, use advanced form extraction and crawling
    if deep_scan and http_client:
        try:
            from brsxss.crawler.engine import CrawlerEngine, CrawlConfig
            from brsxss.crawler.form_extractor import FormExtractor
            
            # Use crawler for comprehensive discovery
            config = CrawlConfig(
                max_depth=2, 
                max_urls=20, 
                max_concurrent=3,
                timeout=15,
                extract_forms=True,
                extract_links=True
            )
            crawler = CrawlerEngine(config, http_client)
            
            # Crawl starting from URL
            crawl_results = await crawler.crawl(url)
            
            form_extractor = FormExtractor()
            
            # Process each crawled page
            for result in crawl_results:
                if result.status_code == 200 and result.content:
                    # Extract forms from each page
                    forms = form_extractor.extract_forms(result.content, result.url)
                    
                    for form in forms:
                        # Add testable form fields as parameters
                        for field in form.testable_fields:
                            # Use intelligent default values
                            if field.field_type.name == 'PASSWORD':
                                parameters[field.name] = "password123"
                            elif field.field_type.name == 'EMAIL':
                                parameters[field.name] = "test@example.com"
                            elif 'search' in field.name.lower() or 'query' in field.name.lower():
                                parameters[field.name] = "search_test"
                            else:
                                parameters[field.name] = "test"
                    
                    # Also extract URL parameters from discovered URLs
                    if hasattr(result, 'discovered_urls'):
                        for discovered_url in result.discovered_urls:
                            if hasattr(discovered_url, 'parameters') and discovered_url.parameters:
                                parameters.update(discovered_url.parameters)
                
        except Exception:
            # Fallback to basic form detection if advanced crawling fails
            try:
                response = await http_client.get(url)
                if response.status_code == 200:
                    import re
                    form_inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', response.text, re.I)
                    for input_name in form_inputs:
                        parameters[input_name] = "test"
            except Exception:
                pass
    
    return parameters


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
    target: str = typer.Argument(
        ...,
        help="Domain or IP address to scan (e.g. example.com, 192.168.1.1)",
        metavar="TARGET"
    ),
    threads: int = typer.Option(
        10,
        "--threads", "-t", 
        help="Concurrency (parallel requests)",
        min=1,
        max=50
    ),
    timeout: int = typer.Option(
        15,
        "--timeout",
        help="Request timeout in seconds",
        min=5,
        max=120
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path for report (defaults to results/json/)"
    ),
    deep: bool = typer.Option(True, "--deep/--no-deep", help="Enable deep scanning (crawling + forms)"),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output with detailed parameter analysis"
    ),
    ml_mode: bool = typer.Option(True, "--ml-mode/--no-ml-mode", help="Enable ML-based vulnerability classification"),
    blind_xss_webhook: Optional[str] = typer.Option(
        None,
        "--blind-xss",
        help="Webhook URL for blind XSS detection"
    ),
    no_ssl_verify: bool = typer.Option(
        False,
        "--no-ssl-verify",
        help="Disable SSL certificate verification (useful for internal/self-signed certs)"
    ),
    safe_mode: bool = typer.Option(True, "--safe-mode/--no-safe-mode", help="Enable safe mode for production scanning"),
    pool_cap: int = typer.Option(10000, "--pool-cap", help="Maximum payload pool size", min=100, max=200000),
    max_payloads: int = typer.Option(500, "--max-payloads", help="Maximum payloads per context", min=1, max=10000),
):
    """Wrapper to run async scan function"""
    return asyncio.run(simple_scan(target, threads, timeout, output, deep, verbose, ml_mode, blind_xss_webhook, no_ssl_verify, safe_mode, pool_cap, max_payloads))

# Create typer app for this command
app = typer.Typer()
app.command()(simple_scan_wrapper)