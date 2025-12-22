#!/usr/bin/env python3
"""
Test Script - Phishing Exploitation Toolkit
Teste rapidement les nouveaux outils
"""

import asyncio
import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.async_executor import AsyncExecutor
from src.tools.phishing_exploit import PhishingExploit
from src.tools.osint_analyzer import OSINTAnalyzer
from src.tools.endpoint_tester import EndpointTester


async def test_phishing_tools():
    """Test tous les outils de phishing"""
    
    executor = AsyncExecutor()
    phishing = PhishingExploit(executor)
    osint = OSINTAnalyzer(executor)
    endpoints = EndpointTester(executor)
    
    domain = "exxspecial.com"
    phone = "+221123456789"
    
    print("\n" + "="*80)
    print("🎯 PHISHING EXPLOITATION TOOLKIT - TEST SUITE")
    print("="*80)
    
    # Test 1: SSRF
    print("\n[1/7] Testing SSRF via /sendSms...")
    try:
        result = await phishing.test_ssrf_sendSms()
        print(f"✅ SSRF Test: {len(result['tests'])} payloads tested")
        if result['critical_findings']:
            print(f"   ⚠️  CRITICAL: {result['critical_findings']}")
    except Exception as e:
        print(f"❌ SSRF Test failed: {e}")
    
    # Test 2: OTP Bypass
    print("\n[2/7] Testing OTP Bypass (Race Condition)...")
    try:
        result = await phishing.test_otp_bypass_race(phone, num_requests=20)
        print(f"✅ OTP Test: {result['requests_sent']} requests sent")
        if result['successful_registrations']:
            print(f"   ⚠️  CRITICAL: {len(result['successful_registrations'])} successful registrations!")
    except Exception as e:
        print(f"❌ OTP Test failed: {e}")
    
    # Test 3: IDOR
    print("\n[3/7] Testing IDOR (Invitation Code Enumeration)...")
    try:
        result = await phishing.test_invitation_code_idor((1000, 1100))
        print(f"✅ IDOR Test: Range 1000-1100 tested")
        if result['valid_codes']:
            print(f"   ⚠️  CRITICAL: {len(result['valid_codes'])} valid codes found!")
    except Exception as e:
        print(f"❌ IDOR Test failed: {e}")
    
    # Test 4: Sensitive Files
    print("\n[4/7] Testing Sensitive Files Exposure...")
    try:
        result = await phishing.test_sensitive_files()
        print(f"✅ Files Test: {len(result['files_found'])} files found")
        if result['files_found']:
            print(f"   ⚠️  CRITICAL: Sensitive files exposed!")
            for f in result['files_found']:
                print(f"      - {f['path']}")
    except Exception as e:
        print(f"❌ Files Test failed: {e}")
    
    # Test 5: CSRF
    print("\n[5/7] Testing CSRF Vulnerability...")
    try:
        result = await phishing.test_csrf_vulnerability()
        print(f"✅ CSRF Test: Completed")
        if result['exploitable']:
            print(f"   ⚠️  CRITICAL: CSRF vulnerability found!")
    except Exception as e:
        print(f"❌ CSRF Test failed: {e}")
    
    # Test 6: DOM XSS
    print("\n[6/7] Testing DOM-based XSS...")
    try:
        result = await phishing.test_dom_xss()
        print(f"✅ DOM XSS Test: Completed")
        if result['exploitable']:
            print(f"   ⚠️  CRITICAL: DOM XSS vulnerability found!")
            print(f"      Patterns: {result['suspicious_patterns']}")
    except Exception as e:
        print(f"❌ DOM XSS Test failed: {e}")
    
    # Test 7: Full OSINT
    print("\n[7/7] Running Full OSINT Analysis...")
    try:
        result = await osint.run_full_osint(domain)
        print(f"✅ OSINT Analysis: Completed")
        print(f"   Phishing Score: {result['risk_assessment']['phishing_score']:.1f}%")
        print(f"   Legitimacy Score: {result['risk_assessment']['legitimacy_score']:.1f}%")
        print(f"   Is Phishing: {result['risk_assessment']['is_phishing']}")
    except Exception as e:
        print(f"❌ OSINT Test failed: {e}")
    
    print("\n" + "="*80)
    print("✅ TEST SUITE COMPLETED")
    print("="*80)
    print("\nNext steps:")
    print("1. Review the results above")
    print("2. If vulnerabilities found, run: run_phishing_exploit_suite()")
    print("3. Use locate_origin() to find real IP behind Cloudflare")
    print("4. Use tactical_recon() on the real IP")
    print("\n")


if __name__ == "__main__":
    asyncio.run(test_phishing_tools())
