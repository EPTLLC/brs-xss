#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 26 Oct 2025 14:15:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Example 01: Basic XSS Scan

This example demonstrates how to perform a basic XSS scan on a single URL
with GET parameters.
"""

import asyncio
from brsxss.core import XSSScanner


async def main():
    """Basic XSS scan example"""

    # Initialize scanner
    print("Initializing BRS-XSS scanner...")
    scanner = XSSScanner(timeout=15, max_concurrent=10, verify_ssl=True)

    # Target URL with parameters
    target_url = "https://example.com/search"
    parameters = {"q": "test query", "page": "1", "filter": "all"}

    print(f"\nScanning: {target_url}")
    print(f"Parameters: {list(parameters.keys())}")

    # Perform scan
    results = await scanner.scan_url(
        url=target_url, method="GET", parameters=parameters
    )

    # Display results
    print(f"\n{'='*60}")
    print("Scan Results")
    print(f"{'='*60}\n")

    if results:
        print(f"Found {len(results)} vulnerabilities:\n")

        for i, vuln in enumerate(results, 1):
            print(f"Vulnerability #{i}:")
            print(f"  Parameter: {vuln.get('parameter', 'N/A')}")
            print(f"  Context: {vuln.get('context', 'N/A')}")
            print(f"  Payload: {vuln.get('payload', 'N/A')[:100]}...")
            print(f"  Severity: {vuln.get('severity', 'N/A')}")
            print(f"  Confidence: {vuln.get('confidence', 0):.2%}")
            print()
    else:
        print("No vulnerabilities found.")

    # Cleanup
    await scanner.close()
    print("Scan complete!")


if __name__ == "__main__":
    asyncio.run(main())
