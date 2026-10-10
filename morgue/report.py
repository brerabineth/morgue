"""Report writers: JSON, CSV, JSONL IOCs, self-contained HTML.

Privacy policy (enforced here, tested in CI):
- every secret-bearing field is masked unless reveal=True
- outputs contain relative paths only
- the HTML file pulls zero external assets: safe on an air-gapped workstation
"""

from __future__ import annotations

import csv
import html
import json
import os
from typing import Optional

from .passwords import mask_password
from .models import ScanResult

MASK = "********"


def _pw(value: str, reveal: bool) -> str:
    return value if reveal else mask_password(value)


def _cookie_value(value: str, reveal: bool) -> str:
    if reveal:
        return value
    if len(value) <= 8:
        return MASK
    return value[:4] + "..." + MASK


def _machine_dict(bundle, reveal: bool) -> dict:
    m = bundle.machine
    guid = m.guid if reveal else (m.guid[:8] + "..." if m.guid else "")
    ip = m.external_ip if reveal else (m.external_ip.split(".")[0] + ".x.x.x" if m.external_ip.count(".") == 3 else m.external_ip)
    return {
        "hostname": m.hostname,
        "username": m.username,
        "domain": m.domain,
        "os": (m.os_name + " " + m.os_version).strip(),
        "guid": guid,
        "external_ip": ip,
        "install_date": m.install_date,
        "language": m.language,
        "build_id": m.build_id if reveal else (m.build_id[:6] + "..." if m.build_id else ""),
    }


def scan_report_dict(scan: ScanResult, reveal: bool = False) -> dict:
    """Structured report matching what the HTML shows."""
    return {
        "tool": "morgue",
        "version": "0.1.0",
        "root": scan.root,
        "family": scan.family,
        "machines": scan.machine_count,
        "files_scanned": scan.files_scanned,
        "counts": {
            "credentials": len(scan.credentials),
            "cookies": len(scan.cookies),
            "autofill": len(scan.autofill),
            "cards": len(scan.cards),
            "wallets": len(scan.wallets),
            "secrets": len(scan.secrets),
            "session_cookies": len(scan.session_flags),
        },
        "machines_detail": [
            {"bundle": b.root, "family": b.family, "machine": _machine_dict(b, reveal),
             "credentials": len(b.credentials), "cookies": len(b.cookies)}
            for b in scan.bundles
        ],
        "credentials": [
            {"url": c.url, "username": c.username, "password": _pw(c.password, reveal),
             "domain": c.domain, "source": c.source_file}
            for c in scan.credentials[:2000]
        ],
        "session_cookies": [
            {"domain": f.domain, "name": f.name, "reason": f.reason}
            for f in scan.session_flags[:500]
        ],
        "secrets": [
            {"kind": s.kind, "value": s.masked_value, "source": s.source_file}
            for s in scan.secrets[:200]
        ],
        "domain_census": [
            {"domain": d, "category": cat, "count": n}
            for d, cat, n in scan.domain_census[:500]
        ],
        "corporate_hits": list(scan.corp_hits),
        "password_hygiene": {
            "total": scan.hygiene.total,
            "unique": scan.hygiene.unique,
            "empty": scan.hygiene.empty,
            "reuse_ratio": scan.hygiene.reuse_ratio,
            "avg_length": scan.hygiene.avg_length,
            "min_length": scan.hygiene.min_length,
            "short": scan.hygiene.short_count,
            "digits_only": scan.hygiene.digits_only,
            "top_reused": scan.hygiene.top_reused,
        },
        "exposure": {
            "score": scan.score.value,
            "band": scan.score.band,
            "reasons": [{"points": r.points, "message": r.message} for r in scan.score.reasons],
        },
        "warnings": scan.warnings[:100],
    }


def write_json(scan: ScanResult, out_path: str, reveal: bool = False) -> None:
    data = scan_report_dict(scan, reveal)
    _write_text(out_path, json.dumps(data, indent=2, ensure_ascii=True) + "\n")


def write_csv(scan: ScanResult, out_path: str, reveal: bool = False) -> None:
    """Credential table: url,login,password,domain,category."""
    from .classify import categorize_domain

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "username", "password", "domain", "category"])
        for c in scan.credentials[:20000]:
            writer.writerow([c.url, c.username, _pw(c.password, reveal), c.domain,
                             categorize_domain(c.domain)])


def write_iocs(scan: ScanResult, out_path: str) -> None:
    """JSONL intel feed: one machine per line, no secrets by design."""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        for b in scan.bundles:
            m = b.machine
            record = {
                "type": "infostealer_victim",
                "family": b.family,
                "hostname": m.hostname,
                "username": m.username,
                "domain": m.domain,
                "guid": m.guid[:8] + "..." if m.guid else "",
                "os": (m.os_name + " " + m.os_version).strip(),
                "credentials": len(b.credentials),
                "cookies": len(b.cookies),
                "top_domains": [d for d, _, _ in scan.domain_census[:10]],
            }
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")


_REPORT_CSS = """
body{background:#0c0e12;color:#c9d1d9;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:2rem}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:1.1rem;letter-spacing:.2em;color:#e6edf3;border-bottom:1px solid #21262d;padding-bottom:.6rem}
h1 span{color:#f85149}
h2{font-size:.85rem;letter-spacing:.15em;color:#8b949e;text-transform:uppercase;margin-top:2rem}
table{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.85rem}
th{text-align:left;color:#8b949e;border-bottom:1px solid #21262d;padding:.35rem .5rem;font-weight:400}
td{border-bottom:1px solid #161b22;padding:.35rem .5rem;overflow-wrap:anywhere}
.score{display:flex;gap:1rem;align-items:baseline;margin:1rem 0}
.score .num{font-size:2.6rem;font-weight:700}
.bar{height:6px;background:#161b22;border-radius:3px;overflow:hidden;margin:.3rem 0}
.bar i{display:block;height:100%}
.band-critical{color:#f85149}.band-high{color:#d29922}.band-medium{color:#d29922}.band-low{color:#3fb950}.band-clean{color:#3fb950}
.fill-critical{background:#f85149}.fill-high{background:#d29922}.fill-medium{background:#d29922}.fill-low{background:#3fb950}
.kv{display:grid;grid-template-columns:12rem 1fr;gap:.15rem .8rem;font-size:.85rem}
.kv b{color:#8b949e;font-weight:400}
.badge{display:inline-block;border:1px solid #30363d;border-radius:4px;padding:.05rem .45rem;margin:0 .25rem .25rem 0;font-size:.75rem;color:#8b949e}
footer{margin-top:3rem;color:#484f58;font-size:.75rem;border-top:1px solid #21262d;padding-top:.8rem}
"""


def write_html(scan: ScanResult, out_path: str, reveal: bool = False) -> None:
    e = html.escape
    band = scan.score.band
    rows = []
    for c in scan.credentials[:400]:
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (e(c.url), e(c.username), e(_pw(c.password, reveal)), e(c.domain))
        )
    cookie_rows = [
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(f.domain), e(f.name), e(f.reason))
        for f in scan.session_flags[:100]
    ]
    secret_rows = [
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(s.kind), e(s.masked_value), e(s.source_file))
        for s in scan.secrets[:50]
    ]
    census_rows = []
    census = scan.domain_census[:12]
    max_count = max([n for _, _, n in census], default=1) or 1
    for d, cat, n in census:
        pct = int(100 * n / max_count)
        census_rows.append(
            "<tr><td>%s</td><td><span class='badge'>%s</span></td><td>%d</td></tr>" % (e(d), e(cat), n)
        )
    reason_rows = [
        "<li><b>+%d</b> %s</li>" % (r.points, e(r.message)) for r in scan.score.reasons
    ] or ["<li>no scored findings</li>"]

    machines = []
    for b in scan.bundles:
        m = b.machine
        machines.append(
            "<div class='kv'>"
            "<b>bundle</b><span>%s</span>"
            "<b>hostname</b><span>%s</span>"
            "<b>user</b><span>%s</span>"
            "<b>guid</b><span>%s</span>"
            "<b>os</b><span>%s</span>"
            "<b>creds / cookies</b><span>%d / %d</span>"
            "</div>"
            % (
                e(b.root), e(m.hostname), e(m.username), e(m.guid[:8] + "...") if m.guid else "-",
                e((m.os_name + " " + m.os_version).strip()), len(b.credentials), len(b.cookies),
            )
        )

    doc = """<!doctype html>
<html><head><meta charset="utf-8"><title>morgue report</title>
<style>%s</style></head><body><div class="wrap">
<h1>MORGUE <span>/</span> infostealer triage</h1>
<p>root: %s &middot; family: %s &middot; machines: %d &middot; files: %d</p>
<h2>exposure score</h2>
<div class="score"><span class="num band-%s">%d</span><span class="band-%s">%s</span></div>
<ul>%s</ul>
<h2>victim machines</h2>
%s
<h2>domain census</h2>
<table><tr><th>domain</th><th>category</th><th>count</th></tr>%s</table>
<h2>session cookies (%d)</h2>
<table><tr><th>domain</th><th>cookie</th><th>why it matters</th></tr>%s</table>
<h2>high-value secrets (%d)</h2>
<table><tr><th>kind</th><th>value</th><th>source</th></tr>%s</table>
<h2>credentials (%d%s)</h2>
<table><tr><th>url</th><th>login</th><th>password</th><th>domain</th></tr>%s</table>
<footer>morgue 0.1.0 - local triage for infostealer logs - %s - processed entirely offline</footer>
</div></body></html>""" % (
        _REPORT_CSS,
        e(scan.root), e(scan.family), scan.machine_count, scan.files_scanned,
        band, scan.score.value, band, band.upper(),
        "".join(reason_rows),
        "".join(machines) or "<p>-</p>",
        "".join(census_rows) or "<tr><td colspan=3>-</td></tr>",
        len(scan.session_flags), "".join(cookie_rows) or "<tr><td colspan=3>-</td></tr>",
        len(scan.secrets), "".join(secret_rows) or "<tr><td colspan=3>-</td></tr>",
        len(scan.credentials), " shown: 400" if len(scan.credentials) > 400 else "",
        "".join(rows) or "<tr><td colspan=4>-</td></tr>",
        "masked" if not reveal else "REVEALED",
    )
    _write_text(out_path, doc)


def _write_text(out_path: str, content: str) -> None:
    parent = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(parent, exist_ok=True)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    os.replace(tmp, out_path)
