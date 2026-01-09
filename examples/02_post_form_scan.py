#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 15 Oct 2025 02:40:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Example 02: POST Form Scanning

This example demonstrates how to scan HTML forms using POST method.
"""

import asyncio
from brsxss.core import XSSScanner


async def main():
    """POST form scan example"""

    print("Initializing scanner for POST form testing...")

    scanner = XSSScanner(timeout=20, max_concurrent=5, verify_ssl=True)

    # Target form URL
    form_url = "https://example.com/contact"

    # Form parameters (name, email, message, etc.)
    form_data = {
        "name": "Test User",
        "email": "test@example.com",
        "subject": "Test Subject",
        "message": "Test message content",
        "phone": "+1234567890",
    }

    print(f"\nScanning POST form: {form_url}")
    print(f"Form fields: {list(form_data.keys())}")

    # Scan with POST method
    results = await scanner.scan_url(url=form_url, method="POST", parameters=form_data)

    # Display results
    print(f"\n{'='*60}")
    print("POST Form Scan Results")
    print(f"{'='*60}\n")

    if results:
        print(f"Found {len(results)} XSS vulnerabilities in form:\n")

        for vuln in results:
            print(f"Field: {vuln.get('parameter')}")
            print(f"Context: {vuln.get('context')}")
            print(f"Severity: {vuln.get('severity')}")
            print(f"Exploitability: {vuln.get('exploitability_score', 0):.2f}")
            print(f"Payload: {vuln.get('payload')[:80]}...")
            print("-" * 60)
    else:
        print("No vulnerabilities found in form.")

    await scanner.close()


if __name__ == "__main__":
    asyncio.run(main())
