"""Bundle assembly: walk a bundle root, classify artifacts, parse lines.

Reading policy:
- text files are read with errors="replace" (log files are crime scenes)
- files are capped (MAX_FILE_BYTES, MAX_LINES) so a junk file cannot stall triage
- every file contributes a relative path only; absolute paths never enter the model
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from . import detect
from .models import AutofillEntry, CardRecord, CookieRecord, Credential, LogBundle, SecretHit, WalletArtifact
from .parsers import (
    looks_like_url,
    parse_autofill_line,
    parse_card_line,
    parse_cookie_line,
    parse_credential_line,
    parse_machine_auto,
)

MAX_LINES = 20000

MACHINE_FILES = detect.MACHINE_INFO_NAMES
CREDENTIAL_FILES = detect.CREDENTIAL_NAMES
COOKIE_FILES = detect.COOKIE_NAMES
AUTOFILL_FILES = detect.AUTOFILL_NAMES
CARD_FILES = detect.CARD_NAMES

SECRET_PATTERNS = (
    ("github_pat", r"github_pat_[A-Za-z0-9_]{20,}"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{30,}"),
    ("stripe_secret", r"sk_live_[A-Za-z0-9]{16,}"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("slack_token", r"xox[baprs]\-[A-Za-z0-9\-]{10,}"),
    ("telegram_bot", r"[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}"),
)

_ARTIFACT_DIR_KINDS = (
    ("telegram", ("telegram", "tdata")),
    ("screenshots", ("screenshots",)),
    ("filezilla", ("filezilla",)),
    ("tox", ("tox",)),
    ("nordvpn", ("nordvpn",)),
)


class _Reader:
    """Bounded, tolerant text reader with a line budget."""

    def __init__(self) -> None:
        self.warned: list = []

    def read_text(self, full_path: str, warn_rel: str) -> Optional[str]:
        try:
            if os.path.getsize(full_path) > detect.MAX_FILE_BYTES:
                self.warned.append("skipped oversized file: %s" % warn_rel)
                return None
            with open(full_path, "r", encoding="utf-8", errors="replace", newline="") as fh:
                return fh.read(detect.MAX_FILE_BYTES)
        except OSError as exc:
            self.warned.append("unreadable file %s (%s)" % (warn_rel, exc.errno or "io"))
            return None

    def read_lines(self, full_path: str, warn_rel: str) -> list:
        text = self.read_text(full_path, warn_rel)
        if text is None:
            return []
        lines = text.splitlines()[:MAX_LINES]
        if len(lines) >= MAX_LINES:
            self.warned.append("line budget hit in %s; output truncated" % warn_rel)
        return lines


def _match_kind(lower_path: str) -> Optional[str]:
    for kind, markers in _ARTIFACT_DIR_KINDS:
        for marker in markers:
            if marker in lower_path:
                return kind
    return None


def _scan_secrets(text: str, source_file: str, out: list) -> None:
    for kind, pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            value = match.group(0)
            masked = value[:8] + "..." + value[-4:] if len(value) > 16 else value[:4] + "..."
            if not any(h.kind == kind and h.masked_value == masked for h in out):
                out.append(SecretHit(kind=kind, masked_value=masked, source_file=source_file))
            if len(out) >= 200:
                return


def parse_bundle(bundle_root: str, scan_root: str, family_hint: str = "") -> LogBundle:
    """Parse one bundle directory into a LogBundle."""
    reader = _Reader()
    rel_root = os.path.relpath(bundle_root, scan_root).replace(os.sep, "/")
    if rel_root == ".":
        rel_root = "."
    files = detect.walk_layout(bundle_root)

    machine_text = _reader_machine_text(reader, bundle_root, files)
    verdict = detect.detect_family(files, machine_text)
    family = family_hint if family_hint in detect.FAMILIES and family_hint != "generic" else verdict.family

    bundle = LogBundle(family=family, root=rel_root, warnings=list(reader.warned))
    bundle.files_seen = len(files)
    machine_seen = False

    for entry in files:
        full = os.path.join(bundle_root, entry.rel)
        rel = entry.rel

        kind = _match_kind(entry.lower_path)
        if kind and kind not in bundle.artifact_kinds:
            bundle.artifact_kinds.append(kind)

        wallet = detect.wallet_in_path(entry.lower_path)
        if wallet:
            name, wkind = wallet
            if not any(w.name == name for w in bundle.wallets):
                bundle.wallets.append(WalletArtifact(name=name, path=rel, kind=wkind))

        is_machine = entry.name in MACHINE_FILES or "userinformation" in entry.lower_path
        if is_machine and not machine_seen:
            text = reader.read_text(full, rel)
            if text:
                bundle.machine = parse_machine_auto(text)
                machine_seen = True
            continue

        if entry.name in CREDENTIAL_FILES or "/passwords/" in "/" + entry.lower_path:
            for line in reader.read_lines(full, rel):
                cred = parse_credential_line(line, rel)
                if cred:
                    bundle.credentials.append(cred)
            continue

        if entry.name in COOKIE_FILES or "/cookies/" in "/" + entry.lower_path:
            for line in reader.read_lines(full, rel):
                rec = parse_cookie_line(line, rel)
                if rec:
                    bundle.cookies.append(rec)
            continue

        if entry.name in AUTOFILL_FILES:
            for line in reader.read_lines(full, rel):
                item = parse_autofill_line(line, rel)
                if item:
                    bundle.autofill.append(item)
            continue

        if entry.name in CARD_FILES:
            for line in reader.read_lines(full, rel):
                card = parse_card_line(line, rel)
                if card:
                    bundle.cards.append(card)
            continue

        if entry.name.endswith(".txt"):
            # content sniff: accept a file as a credential dump only when at
            # least half its non-empty lines parse as credential rows; else
            # it is noise (history, notes) - still swept for secret tokens.
            lines = reader.read_lines(full, rel)
            candidates = [l for l in lines if l.strip()]
            if not candidates:
                continue
            creds = []
            for line in candidates:
                cols = line.split("\t")
                if len(cols) >= 3 and looks_like_url(cols[0].strip()):
                    cred = parse_credential_line(line, rel)
                    if cred:
                        creds.append(cred)
            if creds and len(creds) * 2 >= len(candidates):
                bundle.credentials.extend(creds)
            else:
                _scan_secrets("\n".join(candidates), rel, bundle.secrets)
            continue

    bundle.warnings.extend(reader.warned)
    if family_hint not in detect.FAMILIES and verdict.family == "generic" and bundle.credentials:
        bundle.warnings.append(
            "layout not recognized; generic tabular parsing used (%d credentials)" % len(bundle.credentials)
        )
    return bundle


def _reader_machine_text(reader: _Reader, bundle_root: str, files: list) -> str:
    chunks = []
    for f in files:
        if f.name in MACHINE_FILES or "userinformation" in f.lower_path:
            text = reader.read_text(os.path.join(bundle_root, f.rel), f.rel)
            if text:
                chunks.append(text[:2048])
            if len(chunks) >= 4:
                break
    return "\n".join(chunks)


def parse_json_machine_file(full_path: str) -> Optional[dict]:
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None
