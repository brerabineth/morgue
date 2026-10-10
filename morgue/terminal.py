"""ANSI terminal summary. ASCII only, no emoji, color-safe when piped."""

from __future__ import annotations

import sys
from typing import Optional

from .models import ScanResult

BAND_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[0;31m",
    "medium": "\033[0;33m",
    "low": "\033[0;32m",
    "clean": "\033[0;32m",
}
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"

BANNER = r"""
 ___  ___  ___  ___  ___
| _ \|   \| __||   \| _ \   local triage for
|   /| |) | _| | |) |  _/   infostealer logs
|_|_\|___/|___||___/|_|    v0.1.0"""


def _supports_color(stream) -> bool:
    if stream is None or not hasattr(stream, "isatty"):
        return False
    return bool(stream.isatty())


def _human(n: int) -> str:
    return str(n)


def render(scan: ScanResult, color: Optional[bool] = None, reveal: bool = False) -> str:
    use_color = _supports_color(sys.stdout) if color is None else color

    def paint(text: str, code: str) -> str:
        return "%s%s%s" % (code, text, RESET) if use_color else text

    out = []
    out.append(paint(BANNER, DIM))
    out.append("")
    out.append("  root      : %s" % scan.root)
    out.append("  family    : %s" % paint(scan.family, BOLD))
    out.append("  machines  : %d" % scan.machine_count)
    out.append("  files     : %d" % scan.files_scanned)
    out.append("")

    out.append(paint("  [ victims ]", DIM))
    if not scan.bundles:
        out.append("  (none)")
    else:
        for b in scan.bundles[:20]:
            m = b.machine
            ident = m.hostname or "(hostname?)"
            if m.username:
                ident += "\\" + m.username
            guid = (m.guid[:8] + "...") if m.guid else "-"
            out.append("  %-28s %-8s creds:%-5d cookies:%-5d guid:%s" % (
                ident[:28], b.family, len(b.credentials), len(b.cookies), guid))
    out.append("")

    out.append(paint("  [ counts ]", DIM))
    out.append("  credentials : %-6d cookies : %-6d autofill : %d" % (
        len(scan.credentials), len(scan.cookies), len(scan.autofill)))
    out.append("  cards       : %-6d wallets: %-6d secrets  : %d" % (
        len(scan.cards), len(scan.wallets), len(scan.secrets)))
    out.append("  live session cookies : %d" % len(scan.session_flags))
    out.append("")

    if scan.domain_census:
        out.append(paint("  [ domains ]", DIM))
        for domain, cat, count in scan.domain_census[:8]:
            marker = " <corp>" if domain in scan.corp_hits else ""
            out.append("  %-34s %-16s x%d%s" % (domain[:34], cat, count, marker))
        out.append("")

    if scan.corp_hits:
        out.append(paint("  [ corporate exposure ]", DIM))
        for d in scan.corp_hits[:10]:
            out.append("  %s" % paint(d, BOLD))
        out.append("")

    if scan.session_flags:
        out.append(paint("  [ session hijack surface ]", DIM))
        for f in scan.session_flags[:8]:
            out.append("  %-28s %-26s %s" % (f.domain[:28], f.name[:26], f.reason))
        if len(scan.session_flags) > 8:
            out.append("  ... %d more" % (len(scan.session_flags) - 8))
        out.append("")

    if scan.secrets:
        out.append(paint("  [ high-value secrets ]", DIM))
        for s in scan.secrets[:6]:
            out.append("  %-14s %s  (%s)" % (s.kind, s.masked_value, s.source_file[:40]))
        if len(scan.secrets) > 6:
            out.append("  ... %d more" % (len(scan.secrets) - 6))
        out.append("")

    hy = scan.hygiene
    if hy.total:
        out.append(paint("  [ password hygiene ]", DIM))
        out.append("  total:%-6d unique:%-6d reuse:%-5.0f%% empty:%d" % (
            hy.total, hy.unique, hy.reuse_ratio * 100, hy.empty))
        out.append("  avg len:%-5.1f min len:%-4d <8 chars:%-5d digits-only:%d" % (
            hy.avg_length, hy.min_length, hy.short_count, hy.digits_only))
        for masked, count in hy.top_reused[:3]:
            out.append("  reused x%-3d %s" % (count, masked))
        out.append("")

    score = scan.score
    band_color = BAND_COLORS.get(score.band, RESET)
    bar_width = 40
    filled = int(round(bar_width * score.value / 100))
    bar = ("#" * filled).ljust(bar_width)
    out.append(paint("  [ exposure score ]", DIM))
    out.append("  [%s] %s / 100" % (paint(bar, band_color), paint(str(score.value), BOLD)))
    out.append("  verdict : %s" % paint(score.band.upper(), band_color + BOLD if use_color else BOLD))
    for reason in score.reasons:
        out.append("    +%d %s" % (reason.points, reason.message))
    out.append("")

    if scan.warnings:
        out.append(paint("  [ warnings ]", DIM))
        for w in scan.warnings[:6]:
            out.append("  %s" % w)
        if len(scan.warnings) > 6:
            out.append("  ... %d more" % (len(scan.warnings) - 6))
        out.append("")

    out.append("  %s" % paint("processed locally. nothing uploaded. nothing left the machine.", DIM))
    return "\n".join(out)
