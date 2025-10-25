#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 15 Oct 2025 02:40:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech

Example 04: ML-Enhanced Scanning

This example demonstrates how to use Machine Learning enhancements
for improved context detection and payload effectiveness prediction.
"""

import asyncio
from brsxss.core import XSSScanner, MLIntegration


async def main():
    """ML-enhanced scan example"""
    
    print("Initializing ML-Enhanced Scanner...")
    
    # Initialize ML integration
    ml_integration = MLIntegration(enable_ml=True)
    
    # Initialize scanner (ML will be used automatically if available)
    scanner = XSSScanner(
        timeout=20,
        max_concurrent=15,
        enable_dom_xss=True
    )
    
    target_url = "https://example.com/profile"
    parameters = {
        "username": "testuser",
        "bio": "User biography",
        "website": "https://example.com"
    }
    
    print(f"\nScanning: {target_url}")
    print("ML features enabled:")
    print("  - Context prediction enhancement")
    print("  - Payload effectiveness scoring")
    print("  - Vulnerability severity assessment")
    
    # Perform scan
    results = await scanner.scan_url(
        url=target_url,
        method="POST",
        parameters=parameters
    )
    
    print(f"\n{'='*60}")
    print("ML-Enhanced Scan Results")
    print(f"{'='*60}\n")
    
    if results:
        print(f"Found {len(results)} vulnerabilities:\n")
        
        for vuln in results:
            print(f"Parameter: {vuln.get('parameter')}")
            print(f"Context: {vuln.get('context')}")
            print(f"Severity: {vuln.get('severity')}")
            print(f"Confidence: {vuln.get('confidence', 0):.2%}")
            
            # ML-specific information
            if 'ml_enhanced' in vuln:
                print("ML Enhanced: Yes")
                print(f"ML Confidence: {vuln.get('ml_confidence', 0):.2%}")
            
            print(f"Payload: {vuln.get('payload')[:80]}...")
            print("-" * 60)
    else:
        print("No vulnerabilities found.")
    
    # Show ML statistics
    print("\nML Integration Statistics:")
    stats = ml_integration.get_statistics()
    print(f"  ML Enabled: {stats['ml_enabled']}")
    print(f"  Predictions Made: {stats['predictions_made']}")
    print(f"  ML Enhancements: {stats['ml_enhancements']}")
    print(f"  Enhancement Rate: {stats['enhancement_rate']:.2%}")
    
    # Cleanup
    ml_integration.close()
    await scanner.close()


if __name__ == "__main__":
    asyncio.run(main())

