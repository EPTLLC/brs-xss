#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 15 Oct 2025 02:40:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Example 03: WAF Detection and Bypass

This example demonstrates WAF detection and automatic bypass technique generation.
"""

import asyncio
from brsxss.core import XSSScanner
from brsxss.waf import WAFDetector, EvasionEngine


async def main():
    """WAF bypass example"""
    
    print("Initializing WAF detection and bypass...")
    
    # Target URL
    target_url = "https://example.com/search"
    
    # Step 1: Detect WAF
    print(f"\nStep 1: Detecting WAF on {target_url}...")
    
    waf_detector = WAFDetector()
    detected_wafs = await waf_detector.detect_waf(target_url)
    
    if detected_wafs:
        print("\nWAF Detected:")
        for waf in detected_wafs:
            print(f"  Name: {waf.name}")
            print(f"  Type: {waf.waf_type.value}")
            print(f"  Confidence: {waf.confidence:.2%}")
            print(f"  Detection Method: {waf.detection_method}")
            print()
    else:
        print("No WAF detected.")
    
    # Step 2: Generate bypass payloads
    print("Step 2: Generating WAF bypass payloads...")
    
    evasion_engine = EvasionEngine()
    
    base_payload = "<script>alert(1)</script>"
    
    evasions = evasion_engine.generate_evasions(
        payload=base_payload,
        detected_wafs=detected_wafs,
        max_variations=20
    )
    
    print(f"\nGenerated {len(evasions)} bypass payloads:")
    print("="*80)
    
    for i, evasion in enumerate(evasions[:10], 1):  # Show top 10
        print(f"\n#{i} Technique: {evasion.technique.value}")
        print(f"Success Probability: {evasion.success_probability:.2%}")
        print(f"Payload: {evasion.mutated_payload[:100]}...")
        if evasion.description:
            print(f"Description: {evasion.description}")
    
    # Step 3: Scan with WAF bypass enabled
    print("\n" + "="*80)
    print("Step 3: Scanning with WAF bypass techniques...")
    
    scanner = XSSScanner(timeout=20, max_concurrent=10)
    
    results = await scanner.scan_url(
        url=target_url,
        method="GET",
        parameters={"q": "test"}
    )
    
    if results:
        print(f"\nFound {len(results)} vulnerabilities (WAF bypassed):")
        for vuln in results:
            print(f"  - {vuln.get('parameter')}: {vuln.get('severity')}")
    else:
        print("\nNo vulnerabilities found (WAF may be blocking).")
    
    # Cleanup
    await waf_detector.close()
    await scanner.close()


if __name__ == "__main__":
    asyncio.run(main())

