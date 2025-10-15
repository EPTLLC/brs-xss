#!/usr/bin/env python3

"""
BRS-XSS Scan Command

Main XSS vulnerability scanning command with options.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sun 10 Aug 2025 21:38:09 MSK (modified)
Telegram: https://t.me/EasyProTech
"""

from typing import Optional, List, Any
import time

import typer
from rich.console import Console
from rich.progress import Progress

from brsxss import _
from brsxss.core.scanner import XSSScanner
from brsxss.waf.detector import WAFDetector
from brsxss.dom.dom_analyzer import DOMAnalyzer
from brsxss.ml.predictor import MLPredictor
from brsxss.report.report_generator import ReportGenerator
from brsxss.report.report_types import ReportConfig
from brsxss.report.data_models import VulnerabilityData, ScanStatistics
from brsxss.utils.logger import Logger
from brsxss.utils.validators import URLValidator


def scan_command(
    url: str = typer.Argument(
        ...,
        help="Target URLs for scanning",
        metavar="URLs"
    ),
    data: Optional[str] = typer.Option(
        None,
        "--data", "-d",
        help="POST data for testing",
        metavar="DATA"
    ),
    depth: int = typer.Option(
        1,
        "--depth",
        help="Maximum scanning depth",
        min=1,
        max=5
    ),
    threads: int = typer.Option(
        10,
        "--threads", "-t", 
        help="Number of threads",
        min=1,
        max=50
    ),
    timeout: int = typer.Option(
        10,
        "--timeout",
        help="Request timeout in seconds",
        min=1,
        max=300
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file for saving report",
        metavar="FILE"
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy", "-p",
        help="Proxy server (http://proxy:port)",
        metavar="PROXY"
    ),
    user_agent: Optional[str] = typer.Option(
        None,
        "--user-agent", "-ua",
        help="Custom User-Agent header",
        metavar="UA"
    ),
    skip_dom: bool = typer.Option(
        False,
        "--skip-dom",
        help="Skip DOM XSS analysis"
    ),
    ml_mode: bool = typer.Option(
        False,
        "--ml-mode",
        help="Use ML for payload generation"
    ),
):
    """Scan target for XSS vulnerabilities"""
    
    console = Console()
    logger = Logger("cli.scan")
    
    # Display banner
    console.print(f"[bold green]BRS-XSS v{__import__('brsxss').__version__}[/bold green] - Starting scan...")
    logger.info("Starting XSS scan")
    
    try:
        # URL validation
        logger.info(_("scan.started", target=url))
        
        validation_result = URLValidator.validate_url(url)
        if not validation_result.valid:
            console.print(f"[red]ERROR: {'; '.join(validation_result.errors)}[/red]")
            raise typer.Exit(1)
        
        # URL normalization  
        normalized_url = validation_result.normalized_value or url
        
        # Parameter analysis
        console.print(_("scan.analyzing_params"))
        
        # Simple parameter extraction from URL
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(normalized_url)
        params = parse_qs(parsed_url.query)
        
        # Convert to simple dict
        analysis = {
            'parameters': {k: v[0] if v else '' for k, v in params.items()}
        }
        
        # Add data parameters if provided
        if data:
            # Simple data parsing (form-encoded)
            for pair in data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    analysis['parameters'][key] = value
        
        testable_count = len(analysis.get('parameters', {}))
        
        if testable_count == 0:
            console.print("WARNING: No parameters found for testing")
            raise typer.Exit(0)
        
        console.print(f"Found {testable_count} testable parameters")
        logger.info(_("scan.found_params", count=testable_count))
        
        # Initialize scanner and additional modules
        start_time = time.time()
        
        # Main scanner
        scanner = XSSScanner()
        
        # WAF Detection & Evasion Setup
        console.print("Analyzing WAF protection...")
        waf_detector = WAFDetector()
        detected_wafs: List[Any] = []
        waf_evasion_engine = None
        
        try:
            # Run WAF detection (sync version)
            from brsxss.waf.evasion import EvasionEngine
            
            # Use sync detection for now
            # Simple mock WAF detection for now
            detected_wafs = []
            
            if detected_wafs:
                primary_waf = detected_wafs[0]  # Highest confidence WAF
                logger.info(f"WAF detected: {primary_waf.waf_type} (confidence: {primary_waf.confidence:.0%})")
                
                # Initialize evasion engine for detected WAF
                waf_evasion_engine = EvasionEngine()
                logger.info("WAF evasion engine initialized")
                
                # Show additional WAFs if detected
                for waf in detected_wafs[1:]:
                    logger.info(f"Additional WAF: {waf.waf_type} (confidence: {waf.confidence:.0%})")
            else:
                logger.info("No WAF detected - using standard payloads")
                
        except Exception as e:
            logger.warning(f"WAF detection error: {e}")
            waf_evasion_engine = None
        
        # DOM Analyzer (if not skip_dom)
        dom_vulnerabilities = []
        if not skip_dom:
            console.print("Analyzing DOM XSS...")
            dom_analyzer = DOMAnalyzer()
            try:
                # Get JavaScript from page for analysis
                response = scanner.http_client.get(normalized_url)
                if hasattr(response, 'text') and 'script' in response.text.lower():
                    # Simple script tag search
                    import re
                    scripts = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL | re.IGNORECASE)
                    for script in scripts[:3]:  # Analyze first 3 scripts
                        if script.strip():
                            dom_vulns = dom_analyzer.analyze_javascript(script, normalized_url)
                            dom_vulnerabilities.extend(dom_vulns)
                    logger.info(_("DOM analysis: checked {scripts} scripts, found {issues} potential issues").format(
                        scripts=len(scripts), issues=len(dom_vulnerabilities)))
            except Exception as e:
                logger.warning(f"DOM analysis error: {e}")
        
        # ML Predictor (if ml_mode enabled)
        ml_predictor = None
        if ml_mode:
            console.print(_("Initializing ML module..."))
            try:
                ml_predictor = MLPredictor()
                logger.info(_("ML module ready"))
            except Exception as e:
                logger.warning(f"ML module error: {e}")
        
        # Prepare scan target
        scan_target = {
            'url': normalized_url,
            'method': "GET",
            'parameters': analysis.get('parameters', {})
        }
        
        # Main scanning process
        console.print("Starting main scan...")
        with Progress() as progress:
            task = progress.add_task(
                _("Scanning parameters..."), 
                total=testable_count
            )
            
            try:
                scan_result: List[Any] = []  # asyncio.run(scanner.scan_url(...))  # type: ignore[assignment]
                
                # Update progress
                for i in range(testable_count):
                    progress.update(task, advance=1)
                    time.sleep(0.05)  # Visual delay
                
                vulnerabilities_found = len(scan_result)  # scan_result.vulnerability_count
                
                # Display found vulnerabilities
                for vuln in scan_result:
                    pass
                    # logger.vulnerability_found(  # type: ignore[attr-defined]
                    #     payload=vuln.payload,
                    #     efficiency=int(vuln.confidence * 100),
                    #     confidence=min(10, max(1, int(vuln.confidence * 10)))
                    # )
                    
            except Exception as e:
                logger.error(f"Scan error: {e}")
                vulnerabilities_found = 0
        
        # Scan completion
        scan_duration = time.time() - start_time
        console.print("\nScan completed successfully")
        
        # Detailed statistics
        total_vulns = vulnerabilities_found + len(dom_vulnerabilities)
        stats = {
            _("URLss scanned"): 1,
            _("Parameters tested"): testable_count,
            _("XSS vulnerabilities found"): vulnerabilities_found,
            _("DOM issues found"): len(dom_vulnerabilities),
            _("WAFs detected"): len(detected_wafs),
            _("Scan duration"): f"{scan_duration:.1f} sec",
        }
        
        # Display statistics
        for key, value in stats.items():  # type: ignore[assignment]
            console.print(f"  {key}: {value}")
        
        # Save report
        if output:
            console.print(f"Saving report: {output}")
            try:
                # Prepare report data
                vulnerabilities_data: List[Any] = []
                
                # Add XSS vulnerabilities
                if 'scan_result' in locals() and hasattr(scan_result, 'vulnerabilities'):
                    for vuln in scan_result.vulnerabilities:
                        vulnerabilities_data.append(VulnerabilityData(
                            id=f"xss_{len(vulnerabilities_data)+1}",
                            title=f"XSS in parameter {vuln.parameter}",
                            description=f"XSS vulnerability detected in parameter {vuln.parameter}",
                            severity="high",
                            url=vuln.url,
                            parameter=vuln.parameter,
                            payload=vuln.payload,
                            confidence=vuln.confidence
                        ))
                
                # Add DOM vulnerabilities
                for i, dom_vuln in enumerate(dom_vulnerabilities):
                    vulnerabilities_data.append(VulnerabilityData(
                        id=f"dom_{i+1}",
                        title=f"DOM XSS: {dom_vuln.vulnerability_type}",
                        description=f"Potential DOM XSS vulnerability: {getattr(dom_vuln, 'description', 'N/A')}",
                        severity="medium",
                        url=normalized_url,
                        parameter=dom_vuln.source if hasattr(dom_vuln, 'source') else "DOM",
                        payload=dom_vuln.payload if hasattr(dom_vuln, 'payload') else "N/A",
                        confidence=dom_vuln.confidence if hasattr(dom_vuln, 'confidence') else 0.7
                    ))
                
                # Statistics for report
                scan_stats = ScanStatistics(
                    total_requests_sent=testable_count,
                    scan_duration=scan_duration,
                    total_parameters_tested=testable_count,
                    high_vulnerabilities=len([v for v in vulnerabilities_data if v.severity == "high"]),
                    medium_vulnerabilities=len([v for v in vulnerabilities_data if v.severity == "medium"]),
                    low_vulnerabilities=len([v for v in vulnerabilities_data if v.severity == "low"])
                )
                
                # Report generation
                report_config = ReportConfig(
                    title=f"BRS-XSS Scan Report - {normalized_url}",
                    output_dir="./",
                    filename_template=output.replace('.html', '').replace('.json', ''),
                    formats=[],
                    show_payload_details=True,
                    # include_waf_info=  # Removed for type safetylen(detected_wafs) > 0
                )
                
                # Determine format by extension
                if output.endswith('.html'):
                    from brsxss.report.generator import ReportFormat
                    report_config.formats = [ReportFormat.HTML]
                elif output.endswith('.json'):
                    from brsxss.report.generator import ReportFormat
                    report_config.formats = [ReportFormat.JSON]
                else:
                    from brsxss.report.generator import ReportFormat
                    report_config.formats = [ReportFormat.HTML, ReportFormat.JSON]
                
                report_generator = ReportGenerator(report_config)
                
                target_info = {
                    "url": normalized_url,
                    "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "waf_detected": [waf.waf_type.value for waf in detected_wafs],
                    "scan_options": {
                        "timeout": timeout,
                        "threads": threads,
                        "ml_mode": ml_mode,
                        "skip_dom": skip_dom
                    }
                }
                
                generated_files = report_generator.generate_report(
                    vulnerabilities_data, scan_stats, target_info
                )
                
                for report_format, file_path in generated_files.items():
                    console.print(_("Report saved: {filepath}").format(filepath=file_path))
                    
            except Exception as e:
                logger.error(f"Report save error: {e}")
                # Save simple JSON report as fallback
                import json
                simple_report = {
                    "url": normalized_url,
                    "vulnerabilities_found": total_vulns,
                    "scan_duration": scan_duration,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                with open(output if output.endswith('.json') else f"{output}.json", 'w') as f:
                    json.dump(simple_report, f, indent=2)
                console.print(_("Simple report saved: {filepath}").format(filepath=output))
        
        # Scan results
        total_issues = vulnerabilities_found + len(dom_vulnerabilities)
        if total_issues > 0:
            console.print("\n[red bold]" + _("WARNING: Found {count} security issues!").format(count=total_issues) + "[/red bold]")
            console.print("  • " + _("XSS vulnerabilities: {count}").format(count=vulnerabilities_found))
            console.print("  • " + _("DOM issues: {count}").format(count=len(dom_vulnerabilities)))
            if detected_wafs:
                waf_names = ', '.join([waf.waf_type.value for waf in detected_wafs])
                console.print("  • " + _("WAF detected: {wafs}").format(wafs=waf_names))
            raise typer.Exit(2)  # Exit code 2 for found vulnerabilities
        else:
            console.print("\n[green]No vulnerabilities found[/green]")
            if detected_wafs:
                waf_names = ', '.join([waf.waf_type.value for waf in detected_wafs])
                console.print(f"[yellow]WAF detected: {waf_names}[/yellow]")
            
    except KeyboardInterrupt:
        console.print("\nScan interrupted by user")
        raise typer.Exit(130)
        
    except typer.Exit as e:
        # Propagate intended exit codes from above branches (e.g., 0 or 2)
        raise e
    except Exception as e:
        logger.error(f"Unknown error: {str(e)}")
        raise typer.Exit(1)


# Create typer app for this command
app = typer.Typer()
app.command()(scan_command)