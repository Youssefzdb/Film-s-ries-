#!/usr/bin/env python3
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']

class XSSScanner:
    def __init__(self, url):
        self.url = url
        self.findings = []

    def scan(self):
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        if not params:
            return []
        for param in params:
            for payload in PAYLOADS:
                test_params = dict(params)
                test_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    r = requests.get(test_url, timeout=5)
                    if payload in r.text:
                        print(f"[!] XSS: {test_url}")
                        self.findings.append({"type": "XSS", "url": test_url, "param": param})
                except:
                    pass
        return self.findings
