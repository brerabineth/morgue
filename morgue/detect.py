"""Family detection and bundle discovery.

A "bundle" is one victim log (a directory or a flat file set). Stealer panels
rename folders between builds, so detection is fingerprint-based and
deliberately conservative: name markers first, machine-info content markers
second, content sniffing last. When nothing matches, the generic tabular
parser still gets you usable output - unknown beats wrong.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Optional

FAMILIES = ("redline", "lumma", "stealc", "rhadamanthys", "generic")

MAX_FILES = 5000
MAX_DEPTH = 8
MAX_FILE_BYTES = 32 * 1024 * 1024

# file/dir name markers (lowercased, exact names or suffixes)
MACHINE_INFO_NAMES = frozenset(
    (
        "information.txt", "system info.txt", "system information.txt",
        "info.txt", "userinformation.txt", "user information.txt",
        "client_info.txt", "clientinfo.txt", "machine.txt",
    )
)
CREDENTIAL_NAMES = frozenset(
    ("password.txt", "passwords.txt", "logins.txt", "login.txt", "pass.txt")
)
COOKIE_NAMES = frozenset(("cookies.txt", "cookie.txt"))
AUTOFILL_NAMES = frozenset(("autofill.txt", "forms.txt", "formfields.txt"))
CARD_NAMES = frozenset(("cards.txt", "creditcards.txt", "card.txt"))

WALLET_MARKERS = (
    "metamask", "electrum", "exodus", "atomic wallet", "tronlink", "phantom",
    "ronin", "binance chain", "coin98", "nami", "yoroi", "daedalus",
    "guarda", "trust wallet", "coinbase wallet", "multibit", "monero",
)
WALLET_DESKTOP = frozenset(("electrum", "exodus", "atomic wallet", "multibit", "daedalus", "monero"))


@dataclass
class FamilyVerdict:
    family: str
    confidence: float
    reasons: list = field(default_factory=list)


@dataclass
class LayoutFile:
    """A file discovered inside a candidate bundle root."""

    rel: str              # path relative to the scan root, '/' separators
    name: str             # lowercase file name
    lower_path: str       # lowercase relative path
    size: int


def walk_layout(root: str) -> list:
    """Collect LayoutFile entries under root (bounded walk, no symlink follow)."""
    entries = []
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= MAX_DEPTH:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "node_modules")]
        for fname in filenames:
            if len(entries) >= MAX_FILES:
                return entries
            full = os.path.join(dirpath, fname)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            entries.append(LayoutFile(rel=rel, name=fname.lower(), lower_path=rel.lower(), size=size))
    return entries


def _has(entry_names: set, markers: frozenset) -> bool:
    return bool(entry_names & markers)


def wallet_in_path(lower_path: str) -> Optional[tuple]:
    """Return (wallet_name, kind) when a path contains a known wallet marker."""
    for marker in WALLET_MARKERS:
        if marker in lower_path:
            kind = "desktop" if any(w in lower_path for w in WALLET_DESKTOP) else "extension"
            return (marker, kind)
    return None


def _machine_hint(files: list, opener) -> str:
    """Concatenate machine-info candidates' first bytes for content checks."""
    chunks = []
    for f in files:
        if f.name in MACHINE_INFO_NAMES or "userinformation" in f.lower_path:
            text = opener(f)
            if text:
                chunks.append(text[:2048])
            if len(chunks) >= 4:
                break
    return "\n".join(chunks)


def detect_family(files: list, machine_text: str) -> FamilyVerdict:
    """Score family fingerprints over discovered files + machine info text."""
    names = {f.name for f in files}
    paths = [f.lower_path for f in files]
    reasons = []
    score = {"redline": 0.0, "lumma": 0.0, "stealc": 0.0, "rhadamanthys": 0.0}

    has_password = "password.txt" in names
    has_autofill = "autofill.txt" in names
    has_cookies = "cookies.txt" in names

    if has_password and has_autofill:
        score["lumma"] += 1.0
        reasons.append("password.txt + autofill.txt pair")
    if any(p.startswith("information/") or "userinformation" in p for p in paths):
        score["redline"] += 1.2
        reasons.append("Information/UserInformation layout")
    if "soft.txt" in names or "processes.txt" in names:
        score["redline"] += 0.6
        reasons.append("redline inventory artifacts (Soft/Processes)")
    if "system information.txt" in names or "system info.txt" in names:
        score["lumma"] += 0.7
        reasons.append("system information artifact")
    if "cards.txt" in names:
        score["lumma"] += 0.3
        reasons.append("cards.txt present")
    if any(p.startswith("vault/") for p in paths) or "vault" in {PurePath(p).parts[0] for p in paths if "/" in p}:
        score["stealc"] += 1.2
        reasons.append("vault/ directory layout")
    if any(p.startswith("browser/") and "vault/" not in p for p in paths):
        score["stealc"] += 0.5
        reasons.append("browser/ per-profile layout")
    if "passwords" in {PurePath(p).parts[0] for p in paths if "/" in p} and \
       "cookies" in {PurePath(p).parts[0] for p in paths if "/" in p}:
        score["rhadamanthys"] += 1.0
        reasons.append("Passwords/ + Cookies/ per-browser dirs")
    if "client_info.txt" in names:
        score["rhadamanthys"] += 0.7
        reasons.append("client_info.txt present")

    machine = machine_text.lower()
    if machine:
        if "global id:" in machine or "computer name:" in machine:
            score["redline"] += 0.4
            score["lumma"] += 0.4
            reasons.append("Global ID / Computer name info block")
        if "install date:" in machine:
            score["lumma"] += 0.4
            reasons.append("install date info block")
        if "buildid" in machine.replace(" ", "") or "build id:" in machine:
            score["stealc"] += 0.5
            reasons.append("build id info block")
        if "client" in machine and "info" in machine:
            score["rhadamanthys"] += 0.2

    best = max(score, key=lambda k: score[k])
    if score[best] >= 1.0:
        return FamilyVerdict(family=best, confidence=min(0.95, 0.5 + 0.15 * score[best]), reasons=reasons)
    if score[best] > 0.0:
        return FamilyVerdict(family="generic", confidence=0.3, reasons=reasons + ["weak fingerprint, generic fallback"])
    return FamilyVerdict(family="generic", confidence=0.25, reasons=["no family fingerprint; generic layout"])


def looks_like_bundle(files: list) -> bool:
    """Heuristic: does this file set look like a stealer log at all?"""
    names = {f.name for f in files}
    if _has(names, CREDENTIAL_NAMES) or _has(names, MACHINE_INFO_NAMES):
        return True
    paths = [f.lower_path for f in files]
    if any(p.startswith(("vault/", "information/", "browser/", "passwords/", "cookies/")) for p in paths):
        return True
    if any("userinformation" in p for p in paths):
        return True
    return False


def find_bundles(root: str) -> tuple:
    """Return (bundle_roots, mode). mode is 'single' or 'multi'.

    Decision order:
    1. direct files at root look like a log -> one bundle at root
    2. else, direct child directories that look like logs -> one bundle each
       (folder of many victims)
    3. else, root as one (probably generic) bundle
    """
    files = walk_layout(root)
    if not files:
        return [], "empty"

    direct = [f for f in files if "/" not in f.rel]
    if looks_like_bundle(direct):
        return [root], "single"

    child_files = {}
    for f in files:
        parts = f.rel.split("/", 1)
        if len(parts) == 2:
            child_files.setdefault(parts[0], []).append(f)
    bundle_children = []
    for child in sorted(child_files):
        if looks_like_bundle(child_files[child]):
            bundle_children.append(os.path.join(root, child))
    if bundle_children:
        return bundle_children, "multi"

    return [root], "single" if looks_like_bundle(files) else "fallback"
