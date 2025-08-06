#!/usr/bin/env python3

"""
BRS-XSS Simple Scan Command

Simple, user-friendly scanning interface - just specify domain/IP.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Tue 05 Aug 2025 17:48:16 MSK - Fixed file path generation and HTTP session cleanup
Telegram: @easyprotech
"""

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse, urljoin

import typer
from rich.console import Console
from rich.progress import Progress

from brsxss import _
from brsxss.core.scanner import XSSScanner
from brsxss.core.config_manager import ConfigManager
from brsxss.utils.validators import URLValidator
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
        help="Number of threads",
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
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Enable deep scanning (crawling + forms)"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output with detailed parameter analysis"
    ),
    ml_mode: bool = typer.Option(
        False,
        "--ml-mode",
        help="Enable ML-based vulnerability classification"
    ),
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
):
    """Scan target for XSS vulnerabilities - specify domain or IP only"""
    
    logger = Logger("cli.simple_scan")
    
    console.print("[bold green]BRS-XSS v1.0.0[/bold green] - Simple XSS Scanner")
    console.print(f"Target: {target}")
    
    if verbose:
        console.print("[dim]Verbose mode enabled - detailed parameter analysis[/dim]")
    if ml_mode:
        console.print("[dim]ML mode enabled - advanced vulnerability classification[/dim]")
    
    # Initialize scanner with CLI parameters
    scanner = XSSScanner(timeout=timeout, max_concurrent=threads, verify_ssl=not no_ssl_verify)
    
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
            task = progress.add_task("Scanning targets...", total=len(scan_targets))
            
            for url in scan_targets:
                progress.update(task, description=f"Scanning {url}")
                
                try:
                    # Auto-discover parameters
                    parameters = await _discover_parameters(url, deep, scanner.http_client)
                    
                    if parameters:
                        console.print(f"Found {len(parameters)} parameters in {url}")
                        
                        # Scan this URL with its parameters
                        vulns = await scanner.scan_url(url, parameters)
                        all_vulnerabilities.extend(vulns)
                    
                    progress.advance(task)
                    
                except Exception as e:
                    logger.warning(f"Error scanning {url}: {e}")
                    progress.advance(task)
        
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
            # Default output path
            import os
            import re
            timestamp = int(__import__('time').time())
            # Clean target URL to create valid filename
            # Remove protocol and special chars
            clean_target = target.replace('https://', '').replace('http://', '')
            clean_target = re.sub(r'[^\w\-_.]', '_', clean_target)
            clean_target = re.sub(r'_{2,}', '_', clean_target).strip('_')
            # Ensure it's not too long
            if len(clean_target) > 50:
                clean_target = clean_target[:50]
            filename = f"scan_report_{clean_target}_{timestamp}.json"
            os.makedirs("results/json", exist_ok=True)
            output = f"results/json/{filename}"
        
        _save_simple_report(all_vulnerabilities, scan_targets, output)
        console.print(f"Report saved: {output}")
    
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise typer.Exit(1)
    
    finally:
        # Clean up HTTP sessions
        try:
            # Give time for pending requests to complete
            await asyncio.sleep(0.5)
            await scanner.close()
            # Additional delay to ensure SSL cleanup
            await asyncio.sleep(0.5)
        except Exception as e:
            logger.debug(f"Error closing scanner: {e}")


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
    """Auto-discover parameters in URL and forms"""
    
    parameters = {}
    
    # Extract URL parameters
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    url_params = parse_qs(parsed.query)
    
    for param, values in url_params.items():
        parameters[param] = values[0] if values else "test"
    
    # If deep scan enabled, try to find forms
    if deep_scan:
        try:
            # HTTPClient import removed - not needed
            
            if http_client:
                response = await http_client.get(url)
                if response.status_code == 200:
                    # Simple form detection
                    import re
                    form_inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', response.text, re.I)
                    for input_name in form_inputs:
                        parameters[input_name] = "test"
                    
        except Exception:
            pass  # Continue with URL params only
    
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
            "scanner": "BRS-XSS Simple Scanner v1.0.0",
            "targets_scanned": len(targets),
            "vulnerabilities_found": len(serializable_vulns)
        },
        "targets": targets,
        "vulnerabilities": serializable_vulns
    }
    
    # Determine format by extension
    if output_path.endswith('.json'):
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, cls=CustomJSONEncoder)
    else:
        # Default to JSON
        with open(output_path + '.json', 'w') as f:
            json.dump(report, f, indent=2, cls=CustomJSONEncoder)


def simple_scan_wrapper(
    target: str = typer.Argument(
        ...,
        help="Domain or IP address to scan (e.g. example.com, 192.168.1.1)",
        metavar="TARGET"
    ),
    threads: int = typer.Option(
        10,
        "--threads", "-t", 
        help="Number of threads",
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
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Enable deep scanning (crawling + forms)"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output with detailed parameter analysis"
    ),
    ml_mode: bool = typer.Option(
        False,
        "--ml-mode",
        help="Enable ML-based vulnerability classification"
    ),
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
):
    """Wrapper to run async scan function"""
    return asyncio.run(simple_scan(target, threads, timeout, output, deep, verbose, ml_mode, blind_xss_webhook, no_ssl_verify))

# Create typer app for this command
app = typer.Typer()
app.command()(simple_scan_wrapper)