"""Scanner orchestration: path -> bundles -> ScanResult."""

from __future__ import annotations

import os

from . import bundle as bundle_mod
from . import classify, detect, passwords, scoring
from .models import ScanResult

FAMILY_ALIASES = {"lummac2": "lumma", "redline": "redline", "stealc": "stealc",
                  "rhadamanthys": "rhadamanthys", "generic": "generic"}


def scan_path(root: str, corp_domains=(), family_hint: str = "") -> ScanResult:
    """Scan a directory containing one or many stealer logs."""
    result = ScanResult(root=os.path.basename(os.path.abspath(root)) or root)
    if not os.path.isdir(root):
        raise FileNotFoundError("not a directory: %s" % root)

    corp = frozenset(d.strip().lower() for d in corp_domains if d.strip())
    hint = FAMILY_ALIASES.get(family_hint.strip().lower(), "") if family_hint else ""

    roots, mode = detect.find_bundles(root)
    if mode == "empty":
        result.warnings.append("no files under %s" % root)
        return result

    for bundle_root in roots:
        try:
            b = bundle_mod.parse_bundle(bundle_root, root, family_hint=hint)
        except OSError as exc:
            result.warnings.append("bundle parse failed: %s (%s)" % (bundle_root, exc))
            continue
        result.bundles.append(b)
        result.files_scanned += b.files_seen
        result.warnings.extend("[" + b.root + "] " + w for w in b.warnings)

    if not result.bundles:
        result.warnings.append("no parseable bundles found")
        return result

    # family label: majority vote across bundles, deterministic order
    votes = {}
    for b in result.bundles:
        votes[b.family] = votes.get(b.family, 0) + 1
    result.family = max(votes.items(), key=lambda kv: (kv[1], kv[0]))[0]

    for b in result.bundles:
        result.credentials.extend(b.credentials)
        result.cookies.extend(b.cookies)
        result.autofill.extend(b.autofill)
        result.cards.extend(b.cards)
        result.wallets.extend(b.wallets)
        result.secrets.extend(b.secrets)

    result.session_flags = classify.collect_session_flags(result.cookies)
    result.secrets = classify.scan_secret_values(result.autofill, result.credentials)
    result.hygiene = passwords.analyze(result.credentials)
    result.score = scoring.compute(result, corp)
    return result
