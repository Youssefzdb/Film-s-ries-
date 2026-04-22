#!/usr/bin/env python3
import requests

REQUIRED = {
    "Strict-Transport-Security": "Missing HSTS",
    "Content-Security-Policy": "Missing CSP",
    "X-Frame-Options": "Clickjacking risk",
    "X-Content-Type-Options": "MIME sniffing risk",
}

class HeaderChecker:
    def __init__(self, url):
        self.url = url

    def check(self):
        findings = []
        try:
            r = requests.get(self.url, timeout=5)
            for header, desc in REQUIRED.items():
                if header not in r.headers:
                    print(f"[!] {desc}: {header}")
                    findings.append({"type": "Missing Header", "header": header, "desc": desc})
        except Exception as e:
            print(f"[-] Header check failed: {e}")
        return findings
