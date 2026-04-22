#!/usr/bin/env python3
"""Security Header Checker"""
import requests

REQUIRED_HEADERS = {
    "Strict-Transport-Security": "HSTS missing - MITM risk",
    "X-Frame-Options": "Clickjacking protection missing",
    "X-Content-Type-Options": "MIME sniffing protection missing",
    "Content-Security-Policy": "CSP missing - XSS risk",
    "X-XSS-Protection": "XSS filter header missing",
    "Referrer-Policy": "Referrer policy missing"
}

class HeaderChecker:
    def __init__(self, url):
        self.url = url

    def check(self):
        findings = []
        try:
            r = requests.get(self.url, timeout=5)
            for header, note in REQUIRED_HEADERS.items():
                if header not in r.headers:
                    findings.append({"header": header, "note": note, "severity": "MEDIUM"})
                    print(f"[!] Missing: {header}")
            print(f"[+] Header check: {len(findings)} missing headers")
        except Exception as e:
            findings.append({"error": str(e)})
        return findings
