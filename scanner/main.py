#!/usr/bin/env python3
"""
webshield-scanner - Web Application Vulnerability Scanner
Detects XSS, SQLi, CSRF, open redirects, and misconfigurations
"""
import argparse
from modules.xss_scanner import XSSScanner
from modules.sqli_scanner import SQLiScanner
from modules.header_checker import HeaderChecker
from modules.crawler import WebCrawler
from modules.report import HTMLReport

def main():
    parser = argparse.ArgumentParser(description="WebShield Scanner")
    parser.add_argument("url", help="Target URL (e.g. http://example.com)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument("--output", default="webshield_report.html")
    args = parser.parse_args()

    print(f"[*] WebShield Scanner starting on: {args.url}")
    
    crawler = WebCrawler(args.url, args.depth)
    urls = crawler.crawl()
    print(f"[+] Discovered {len(urls)} URLs")

    results = {"xss": [], "sqli": [], "headers": {}, "urls": urls}

    for url in urls:
        xss = XSSScanner(url)
        results["xss"].extend(xss.scan())

        sqli = SQLiScanner(url)
        results["sqli"].extend(sqli.scan())

    header_check = HeaderChecker(args.url)
    results["headers"] = header_check.check()

    report = HTMLReport(args.url, results)
    report.save(args.output)
    print(f"[+] Report saved: {args.output}")

if __name__ == "__main__":
    main()

