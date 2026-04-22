#!/usr/bin/env python3
from datetime import datetime

class Report:
    def __init__(self, results):
        self.r = results

    def save(self, filename):
        items = self.r.get("sqli",[]) + self.r.get("xss",[]) + self.r.get("headers",[]) + self.r.get("ssl",[])
        rows = "".join(f"<tr><td>{i.get('type','')}</td><td>{i.get('url',i.get('header',i.get('desc','')))}</td></tr>" for i in items)
        html = f"""<!DOCTYPE html><html><head><title>WebShield</title>
<style>body{{font-family:Arial;background:#0d1117;color:#c9d1d9;padding:20px}}h1{{color:#58a6ff}}
table{{width:100%;border-collapse:collapse}}td,th{{padding:8px;border:1px solid #30363d}}th{{background:#21262d}}</style></head>
<body><h1>WebShield Report</h1><p>Target: <b>{self.r['target']}</b> | {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<table><tr><th>Type</th><th>Detail</th></tr>{rows}</table></body></html>"""
        with open(filename, "w") as f:
            f.write(html)
