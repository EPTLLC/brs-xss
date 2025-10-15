#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 15 Oct 2025 02:40:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Example 05: Full Website Scan with Crawler

This example demonstrates how to perform a scan of an entire
website using the crawler to discover entry points.
"""

import asyncio
from brsxss.core import XSSScanner
from brsxss.crawler import CrawlerEngine
from brsxss.report import ReportGenerator, ReportFormat


async def main():
    """Full website scan with crawler"""
    
    target_domain = "https://example.com"
    
    print("="*80)
    print("BRS-XSS: Full Website Security Scan")
    print("="*80)
    print(f"\nTarget: {target_domain}")
    print(f"Mode: (Crawl + Scan + Report)")
    print()
    
    # Step 1: Crawl website
    print("Step 1: Crawling website...")
    print("-" * 80)
    
    crawler = CrawlerEngine(
        max_depth=3,
        max_pages=50,
        respect_robots=True
    )
    
    entry_points = await crawler.crawl(target_domain)
    
    print(f"Found {len(entry_points)} entry points:")
    print(f"  - GET endpoints: {sum(1 for ep in entry_points if ep.method == 'GET')}")
    print(f"  - POST endpoints: {sum(1 for ep in entry_points if ep.method == 'POST')}")
    print(f"  - Total parameters: {sum(len(ep.parameters) for ep in entry_points)}")
    print()
    
    # Step 2: Scan all entry points
    print("Step 2: Scanning entry points for XSS...")
    print("-" * 80)
    
    scanner = XSSScanner(
        timeout=20,
        max_concurrent=20,
        enable_dom_xss=True
    )
    
    all_vulnerabilities = []
    
    for i, entry_point in enumerate(entry_points, 1):
        print(f"Scanning {i}/{len(entry_points)}: {entry_point.url}")
        
        try:
            vulns = await scanner.scan_url(
                url=entry_point.url,
                method=entry_point.method,
                parameters=entry_point.parameters
            )
            
            if vulns:
                all_vulnerabilities.extend(vulns)
                print(f"  → Found {len(vulns)} vulnerabilities")
        except Exception as e:
            print(f"  → Error: {e}")
    
    print()
    print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
    print()
    
    # Step 3: Generate reports
    print("Step 3: Generating reports...")
    print("-" * 80)
    
    reporter = ReportGenerator()
    
    # Generate SARIF report (for GitHub Security)
    sarif_file = "scan_results.sarif"
    reporter.generate_report(
        all_vulnerabilities,
        format=ReportFormat.SARIF,
        output_file=sarif_file
    )
    print(f"  ✓ SARIF report: {sarif_file}")
    
    # Generate HTML report (for human review)
    html_file = "scan_results.html"
    reporter.generate_report(
        all_vulnerabilities,
        format=ReportFormat.HTML,
        output_file=html_file
    )
    print(f"  ✓ HTML report: {html_file}")
    
    # Generate JSON report (for automation)
    json_file = "scan_results.json"
    reporter.generate_report(
        all_vulnerabilities,
        format=ReportFormat.JSON,
        output_file=json_file
    )
    print(f"  ✓ JSON report: {json_file}")
    
    # Step 4: Summary
    print()
    print("="*80)
    print("Scan Summary")
    print("="*80)
    print(f"Target: {target_domain}")
    print(f"Entry Points Scanned: {len(entry_points)}")
    print(f"Vulnerabilities Found: {len(all_vulnerabilities)}")
    
    if all_vulnerabilities:
        severity_counts = {}
        for vuln in all_vulnerabilities:
            sev = vuln.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print("\nBy Severity:")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")
    
    print("\nReports Generated:")
    print(f"  - {sarif_file} (GitHub Security)")
    print(f"  - {html_file} (Human Review)")
    print(f"  - {json_file} (Automation)")
    print()
    
    # Cleanup
    await crawler.close()
    await scanner.close()
    
    print("Scan complete!")


if __name__ == "__main__":
    asyncio.run(main())

