"""Domain classification, corporate hit detection, session-cookie flags."""

from __future__ import annotations

import re
from typing import Optional

from .models import AutofillEntry, CookieRecord, Credential, SecretHit, SessionCookieFlag

# ordered: first match wins
CATEGORY_RULES = (
    ("crypto_exchange", (
        "binance.com", "coinbase.com", "kraken.com", "okx.com", "bybit.com",
        "kucoin.com", "gemini.com", "bitfinex.com", "bitget.com", "mexc.com",
        "htx.com", "huobi.com", "crypto.com", "gate.io", "deribit.com",
        "bitstamp.net", "poloniex.com", "bitflyer.com", "luno.com",
    )),
    ("corporate_sso", (
        "okta.com", "oktapreview.com", "jumpcloud.com", "duosecurity.com",
        "login.microsoftonline.com", "sts.windows.net", "myapps.microsoft.com",
        "onelogin.com", "pingone.com", "sso.", "auth0.com", "workday.com",
        "slack.com/ssosignin", "google.com/a/",
    )),
    ("cloud_console", (
        "console.aws.amazon.com", "signin.aws.amazon.com", "portal.azure.com",
        "console.cloud.google.com", "cloud.digitalocean.com", "cloud.linode.com",
        "console.hetzner.cloud", "dash.cloudflare.com", "vultr.com",
        "portal.azure.com.bak", "app.terraform.io", "console.heroku.com",
    )),
    ("dev_platform", (
        "github.com", "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
        "hub.docker.com", "registry-1.docker.io", "sourceforge.net",
        "dev.azure.com", "jetbrains.com", "vercel.com", "netlify.com",
    )),
    ("vpn_provider", (
        "nordvpn.com", "expressvpn.com", "protonvpn.com", "mullvad.net",
        "surfshark.com", "privateinternetaccess.com", "ipvanish.com",
        "cyberghostvpn.com", "windscribe.com", "torguard.net", "azirevpn.com",
    )),
    ("banking_fintech", (
        "chase.com", "wellsfargo.com", "bankofamerica.com", "citi.com",
        "revolut.com", "wise.com", "paypal.com", "stripe.com", "adyen.com",
        "squarespace.com", "shopify.com", " Klarna.com", "klarna.com",
        "transferwise.com", "payoneer.com", "wise.io", "capitalone.com",
    )),
    ("email_provider", (
        "gmail.com", "mail.google.com", "outlook.com", "outlook.live.com",
        "protonmail.com", "proton.me", "mail.proton.me", "yahoo.com",
        "zoho.com", "mail.ru", "yandex.ru", "icloud.com", "gmx.com",
        "mail.yahoo.com", "tutanota.com", "tuta.io",
    )),
    ("social", (
        "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
        "reddit.com", "discord.com", "tiktok.com", "web.telegram.org",
        "telegram.org", "vk.com", "snapchat.com", "pinterest.com", "threads.net",
    )),
    ("marketplace", (
        "amazon.com", "ebay.com", "aliexpress.com", "etsy.com", "walmart.com",
        "temu.com", "shein.com", "flipkart.com", "avito.ru", "olx.com",
    )),
    ("streaming", (
        "netflix.com", "spotify.com", "youtube.com", "twitch.tv", "hulu.com",
        "disneyplus.com", "hbo.com", "primevideo.com", "crunchyroll.com",
    )),
)

# exact cookie names that equal a live, replayable session
SESSION_COOKIE_NAMES = {
    "auth_token",                      # X/Twitter
    "__secure-1psid", "__secure-3psid", "__secure-1psidts",  # Google
    "ssid", "sapigs", "hsid", "lsid",  # Google legacy
    ".aspxauth",                       # ASP.NET forms auth
    "jsessionid", "phpsessid", "sessionid",  # Java/PHP/Django
    "connect.sid",                     # Express
    "wordpress_logged_in",
    "steamloginsecure",
    "remixsid",                        # VK
    "remember_web",                    # Laravel
    "__secure-next-auth.session-token", "__host-next-auth.session-token",
    "cf_clearance",                    # Cloudflare clearance (bypass aid)
    "laravel_session",
    "mstokencache", "estsauth", "estsauthpersistent",  # Microsoft ESTS
}

# cookies whose NAME suggests auth on unknown domains
_SESSION_NAME_HINTS = ("sess", "token", "auth", "session")

CORP_SUFFIX_HINTS = (
    "sso.", "mail.", "vpn.", "portal.", "intranet.", "git.", "jira.",
    "confluence.", "remote.", "owa.", "webmail.",
)

_SECRET_VALUE_RE = re.compile(
    r"(github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|"
    r"sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|"
    r"xox[baprs]\-[A-Za-z0-9\-]{10,})"
)


def categorize_domain(domain: str) -> str:
    """Return the first matching category for a domain, else 'other'."""
    d = (domain or "").lower().strip(".")
    if not d:
        return "other"
    full = d if d.startswith(".") else "." + d
    for category, needles in CATEGORY_RULES:
        for needle in needles:
            needle = needle.lower().strip()
            if needle.endswith(".") or needle.startswith("."):
                if needle.strip(".") in d or full.find(needle) >= 0:
                    return category
            elif d == needle or d.endswith("." + needle):
                return category
            if needle in d:  # path-like or subdomain markers (sso., /a/)
                return category
    return "other"


def is_corporate(domain: str, corp_domains: frozenset) -> bool:
    """True when domain equals or is a subdomain of a watched corp domain."""
    d = (domain or "").lower().strip(".")
    if not d:
        return False
    for corp in corp_domains:
        corp = corp.lower().strip(".")
        if d == corp or d.endswith("." + corp):
            return True
    return False


def session_flag(cookie: CookieRecord) -> Optional[str]:
    """Reason string when a cookie grants a replayable session, else None."""
    name = cookie.name.lower()
    if name in SESSION_COOKIE_NAMES:
        return "known session cookie (%s)" % cookie.name
    if any(h in name for h in _SESSION_NAME_HINTS) and len(cookie.value) >= 20:
        return "session-like cookie on %s" % cookie.domain
    return None


def collect_session_flags(cookies: list) -> list:
    flags = []
    seen = set()
    for c in cookies:
        reason = session_flag(c)
        if reason:
            key = (c.domain, c.name)
            if key not in seen:
                seen.add(key)
                flags.append(SessionCookieFlag(domain=c.domain, name=c.name, reason=reason))
    return flags


def scan_secret_values(autofill: list, credentials: list) -> list:
    """Find API keys / tokens pasted into autofill values or password fields."""
    hits = []
    seen = set()
    sources = [(a.value, a.source_file) for a in autofill]
    sources += [(c.password, c.source_file) for c in credentials]
    for value, source in sources:
        if not value:
            continue
        for match in _SECRET_VALUE_RE.finditer(value):
            token = match.group(0)
            masked = token[:8] + "..." + token[-4:]
            key = (token[:8], token[-4:])
            if key not in seen:
                seen.add(key)
                kind = _kind_of(token)
                hits.append(SecretHit(kind=kind, masked_value=masked, source_file=source))
    return hits


def _kind_of(token: str) -> str:
    if token.startswith("github_pat_"):
        return "github_pat"
    if re.match(r"^gh[pousr]_", token):
        return "github_token"
    if token.startswith("sk_live_"):
        return "stripe_secret"
    if token.startswith("AKIA"):
        return "aws_access_key"
    if token.startswith("AIza"):
        return "google_api_key"
    return "slack_token"


def looks_corporate(domain: str) -> bool:
    """Cheap heuristic: subdomain markers that suggest corporate infrastructure."""
    d = (domain or "").lower()
    return any(d.startswith(h) or ("." + h) in d for h in CORP_SUFFIX_HINTS)
