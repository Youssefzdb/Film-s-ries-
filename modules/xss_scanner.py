#!/usr/bin/env python3
"""XSS Scanner"""
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
]

class XSSScanner:
    def __init__(self, url):
        self.url = url

    def scan(self):
        findings = []
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        
        if not params:
            return findings
        
        for param in params:
            for payload in PAYLOADS:
                test_params = dict(params)
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    r = requests.get(test_url, timeout=5)
                    if payload in r.text:
                        findings.append({
                            "type": "XSS",
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "severity": "HIGH"
                        })
                        print(f"[!] XSS: {self.url} | param={param}")
                        break
                except:
                    pass
        return findings
