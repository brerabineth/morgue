"""Enterprise exposure scoring.

The question scoring answers: "a log from this machine just surfaced -
how bad is it for the org it belongs to?" Points are additive with a hard
cap of 100, and every contribution keeps its reason so the number is
defensible in a client report.
"""

from __future__ import annotations

from .classify import categorize_domain, is_corporate, looks_corporate
from .models import ExposureScore, ScoreReason, ScanResult

BANDS = (
    (70, "critical"),
    (40, "high"),
    (20, "medium"),
    (1, "low"),
    (0, "clean"),
)


def band_of(value: int) -> str:
    for threshold, band in BANDS:
        if value >= threshold:
            return band
    return "clean"


def compute(scan: ScanResult, corp_domains: frozenset = frozenset()) -> ExposureScore:
    score = ExposureScore()
    total = 0

    def add(points: int, message: str) -> None:
        nonlocal total
        total = min(100, total + points)
        score.reasons.append(ScoreReason(points=points, message=message))

    # 1. corporate domain seen in credentials
    if corp_domains:
        corp_seen = sorted(
            {c.domain for c in scan.credentials if is_corporate(c.domain, corp_domains)}
        )
        scan.corp_hits = corp_seen
        if corp_seen:
            add(min(50, 25 * len(corp_seen)),
                "corporate domain in stolen logins: %s" % ", ".join(corp_seen[:5]))

    # 2. domain census by category (classify on the full host so subdomain
    #    markers like login./sso./console. survive)
    census = {}
    for cred in scan.credentials:
        key = cred.host or cred.domain
        if not key:
            continue
        cat = categorize_domain(key)
        census.setdefault(cat, {})
        census[cat][key] = census[cat].get(key, 0) + 1
    scan.domain_census = [
        (domain, cat, count)
        for cat, domains in census.items()
        for domain, count in sorted(domains.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    if "corporate_sso" in census:
        domains = sorted(census["corporate_sso"])
        add(20, "identity provider / SSO logins present (%s)" % ", ".join(domains[:3]))
    if "cloud_console" in census:
        add(15, "cloud console logins present (%s)" % ", ".join(sorted(census["cloud_console"])[:3]))
    if "dev_platform" in census:
        add(10, "code platform logins present (%s)" % ", ".join(sorted(census["dev_platform"])[:3]))
    if "crypto_exchange" in census:
        add(15, "crypto exchange logins present")
    if "vpn_provider" in census:
        add(10, "VPN provider logins present")
    if "banking_fintech" in census:
        add(10, "banking / fintech logins present")

    # 3. infrastructure-looking hosts not on public lists (portal.*, vpn.*, ...)
    infra = sorted(
        {
            c.domain
            for c in scan.credentials
            if looks_corporate(c.host or c.domain) and c.domain not in corp_domains
        }
    )
    if infra and "corporate_sso" not in census:
        add(10, "self-hosted infra logins look corporate (%s)" % ", ".join(infra[:3]))

    # 4. live session cookies
    if scan.session_flags:
        corp_cookie_domains = sorted(
            {
                f.domain
                for f in scan.session_flags
                if corp_domains and is_corporate(f.domain, corp_domains)
            }
        )
        if corp_cookie_domains:
            add(20, "replayable session cookies on corporate domains")
        elif "corporate_sso" in census:
            sso_suffixes = tuple(s for s in ("okta.com", "onelogin.com", "auth0.com", "login.microsoftonline.com"))
            if any(any(d.endswith(s) for s in sso_suffixes) for d in (f.domain for f in scan.session_flags)):
                add(20, "replayable session cookies on identity provider domains")
        if len({(f.domain, f.name) for f in scan.session_flags}) >= 10:
            add(10, "wide live-session surface (%d unique session cookies)" % len(scan.session_flags))

    # 5. high-value secrets
    if scan.secrets:
        kinds = sorted({s.kind for s in scan.secrets})
        add(15, "high-value API tokens in stolen data (%s)" % ", ".join(kinds[:4]))

    # 6. cards and wallets
    if scan.cards:
        add(10, "%d payment card record(s) present" % len(scan.cards))
    if scan.wallets:
        add(5, "crypto wallet artifacts present (%s)" % ", ".join(sorted({w.name for w in scan.wallets})[:4]))

    score.value = total
    score.band = band_of(total)
    return score
