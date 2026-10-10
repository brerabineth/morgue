"""Password hygiene analytics over extracted credentials."""

from __future__ import annotations

import math
from collections import Counter

from .models import Credential, PasswordHygiene


def mask_password(password: str) -> str:
    """Stable, shareable mask: keep first char and length hint only."""
    if not password:
        return "(empty)"
    head = password[0]
    return "%s%s(len=%d)" % (head, "*" * min(len(password), 12), len(password))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def analyze(credentials: list) -> PasswordHygiene:
    """Aggregate hygiene metrics. Masked everywhere - never emits plaintext."""
    hy = PasswordHygiene()
    hy.total = len(credentials)
    if hy.total == 0:
        return hy

    passwords = [c.password for c in credentials]
    nonempty = [p for p in passwords if p]
    hy.empty = hy.total - len(nonempty)
    counts = Counter(nonempty)
    hy.unique = len(counts)
    reused = sum(n for _, n in counts.items() if n > 1)
    hy.reuse_ratio = round(reused / hy.total, 3) if hy.total else 0.0

    if nonempty:
        lengths = [len(p) for p in nonempty]
        hy.avg_length = round(sum(lengths) / len(lengths), 1)
        hy.min_length = min(lengths)
        hy.short_count = sum(1 for n in lengths if n < 8)
        hy.digits_only = sum(1 for p in nonempty if p.isdigit())

    hy.top_reused = [
        (mask_password(pw), n)
        for pw, n in counts.most_common(5)
        if n > 1
    ]
    return hy
