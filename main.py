#!/usr/bin/env python3
"""webshield-scanner - Web Application Vulnerability Scanner"""
import argparse
from modules.crawler import Crawler
from modules.sqli import SQLiScanner
from modules.xss import XSSScanner
from modules.headers import HeaderChecker
from modules.ssl_checker import SSLChecker
from modules.report import Report

def main():
    parser = argparse.ArgumentParser(description="webshield-scanner")
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument("--output", default="webshield_report.html")
    args = parser.parse_args()

    print(f"[*] WebShield Scanner starting on: {args.url}")
    results = {"target": args.url, "sqli": [], "xss": [], "headers": [], "ssl": []}

    # Crawl
    crawler = Crawler(args.url, args.depth)
    urls = crawler.crawl()
    print(f"[+] Found {len(urls)} URLs")

    # Checks
    results["headers"] = HeaderChecker(args.url).check()
    results["ssl"] = SSLChecker(args.url).check()
    
    for url in urls[:20]:
        results["sqli"] += SQLiScanner(url).scan()
        results["xss"] += XSSScanner(url).scan()

    Report(results).save(args.output)
    print(f"[+] Done! Report: {args.output}")

if __name__ == "__main__":
    main()
