"""forge - synthetic infostealer log generator.

Generates realistic-shaped but entirely fake log bundles for training,
tooling demos and regression tests. Every domain is reserved or documented
(RFC 2606 .example / RFC 5737 hosts), every credential is generated, every
cookie value is random bytes. Deterministic under a fixed seed: identical
seed + parameters produce byte-identical trees (asserted in tests).

forge never touches real stolen data and never encodes real credentials.
"""

from __future__ import annotations

import os
import random
import string

FIRST = ("alex", "maria", "kevin", "sandra", "pavel", "diana", "marcus", "laura",
         "igor", "nina", "felix", "olga", "diego", "emma", "viktor", "helen")
LAST = ("r", "m", "k", "s", "p", "d", "w", "t")
WEAK_PASSWORDS = ("password1", "qwerty123", "12345678", "iloveyou", "admin123",
                  "letmein1", "welcome1", "dragon88", "summer2019", "hunter2")
STRONG_POOL = string.ascii_letters + string.digits + "!@#$%^&*"

# domains that are safe to put in synthetic logs
EXAMPLE_DOMAINS = (
    "mail.example.com", "portal.acme-corp.example", "sso.acme-corp.example",
    "gitlab.acme-corp.example", "vpn.acme-corp.example", "crm.example.com",
    "shop.example.com", "forum.example.org", "docs.example.net",
    "login.example.org", "wallet.example.com", "intranet.acme-corp.example",
)
PUBLIC_DOMAINS = (
    "github.com", "login.microsoftonline.com", "web.telegram.org",
    "www.reddit.com", "outlook.live.com", "steamcommunity.com",
    "coinbase.com", "binance.com", "nordvpn.com", "console.aws.amazon.com",
)
COOKIE_NAMES = ("PHPSESSID", "sessionid", "auth_token", "__Secure-1PSID",
                "cf_clearance", "connect.sid", "JSESSIONID", "remember_web")
AUTOFILL_NAMES = ("email", "fullName", "phone", "address", "cc-holder",
                  "billing-address", "company", "username", "notes")
BROWSERS = ("Chrome", "Firefox", "Edge", "Brave", "Opera")


def _rand_password(rng: random.Random, strong: bool) -> str:
    if not strong:
        return rng.choice(WEAK_PASSWORDS)
    length = rng.randint(10, 18)
    return "".join(rng.choice(STRONG_POOL) for _ in range(length))


def _rand_cookie_value(rng: random.Random) -> str:
    return "".join(rng.choice(string.ascii_letters + string.digits + "_-") for _ in range(rng.randint(28, 64)))


def _rand_guid(rng: random.Random) -> str:
    return "%08x-%04x-%04x-%04x-%012x" % (
        rng.getrandbits(32), rng.getrandbits(16), rng.getrandbits(16),
        rng.getrandbits(16), rng.getrandbits(48),
    )


def _machine(rng: random.Random) -> dict:
    user = rng.choice(FIRST) + str(rng.randint(10, 99))
    host = "WS-" + "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    return {
        "user": user, "host": host,
        "guid": _rand_guid(rng),
        "os": rng.choice(("Windows 10 Pro", "Windows 11 Home", "Windows 10 Home")),
        "lang": rng.choice(("en-US", "es-ES", "de-DE", "ru-RU")),
        "ip": "192.0.2.%d" % rng.randint(2, 254),  # RFC 5737 doc range
    }


def _creds(rng: random.Random, count: int, machine: dict) -> list:
    rows = []
    pool = EXAMPLE_DOMAINS + PUBLIC_DOMAINS
    # force corporate hits so scores/demos exercise the interesting path
    forced = ["https://portal.acme-corp.example/", "https://sso.acme-corp.example/"]
    urls = forced + [rng.choice(pool) for _ in range(max(0, count - len(forced)))]
    for url in urls:
        scheme = "https://" if url.startswith("http") is False else ""
        full = url if url.startswith("http") else scheme + url
        login = (machine["user"] if rng.random() < 0.4
                 else rng.choice(FIRST) + "." + rng.choice(LAST) + "@example.com")
        strong = rng.random() < 0.5
        rows.append((full, login, _rand_password(rng, strong)))
    return rows


def _write(path: str, content: str) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)


def forge(out_dir: str, family: str = "lumma", seed: int = 1337,
          creds: int = 40, cookies: int = 30) -> str:
    """Generate one synthetic log bundle. Returns the bundle root path."""
    family = family.strip().lower()
    if family not in ("redline", "lumma", "stealc"):
        raise ValueError("forge family must be redline|lumma|stealc, got %r" % family)
    if creds < 1 or creds > 5000 or cookies < 0 or cookies > 5000:
        raise ValueError("creds/cookies out of range (1..5000 / 0..5000)")

    rng = random.Random(seed)
    machine = _machine(rng)
    cred_rows = _creds(rng, creds, machine)
    root = os.path.join(out_dir, family)
    NL = "\n"

    # shared datasets
    machine_block_lumma = NL.join((
        "Computer name: %s" % machine["host"],
        "User name: %s" % machine["user"],
        "Domain: WORKGROUP",
        "OS: %s" % machine["os"],
        "System language: %s" % machine["lang"],
        "Install date: 2025-%02d-%02d 1%d:%02d:00" % (rng.randint(1, 12), rng.randint(1, 28), rng.randint(0, 9), rng.randint(0, 59)),
        "CPU: Intel(R) Core(TM) i%d-%d" % (rng.randint(3, 9), rng.randint(1000, 9999)),
        "RAM: %d GB" % rng.choice((8, 16, 32)),
        "IP: %s" % machine["ip"],
        "Global ID: {%s}" % machine["guid"].upper(),
    ))
    cookie_rows = []
    for _ in range(cookies):
        domain = rng.choice(EXAMPLE_DOMAINS + ("www.example.com", "www.example.org"))
        name = rng.choice(COOKIE_NAMES)
        flag = "TRUE"
        path = "/"
        expiry = rng.randint(1735689600, 1893456000)
        value = _rand_cookie_value(rng)
        cookie_rows.append((domain, flag, path, expiry, name, value))

    if family == "lumma":
        _write(os.path.join(root, "System Information.txt"), machine_block_lumma + NL)
        _write(os.path.join(root, "Password.txt"),
               NL.join("%s\t%s\t%s" % (u, l, p) for u, l, p in cred_rows) + NL)
        _write(os.path.join(root, "Cookies.txt"),
               NL.join("\t".join((d, f, pth, str(e), n, v)) for d, f, pth, e, n, v in cookie_rows) + NL)
        _write(os.path.join(root, "Autofill.txt"), NL.join((
            "email\t%s@example.com" % machine["user"],
            "fullName\t%s %s" % (rng.choice(FIRST).capitalize(), "Example"),
            "phone\t+1-555-01%02d" % rng.randint(0, 99),
            "company\tExample Corp",
        )) + NL)
        _write(os.path.join(root, "Cards.txt"), NL.join((
            "411111111111%d\t%02d/2%d" % (rng.randint(1000, 9999), rng.randint(1, 12), rng.randint(6, 9)),
        )) + NL)
        _write(os.path.join(root, "Wallets", "MetaMask", "notes.txt"),
               "recovery phrase %d words: %s\n" % (12, " ".join("word%02d" % i for i in range(1, 13))))
        _write(os.path.join(root, "Telegram", "tdata", "key.bin"),
               bytes(rng.getrandbits(8) for _ in range(64)).hex() + NL)

    elif family == "redline":
        _write(os.path.join(root, "Information", "UserInformation", "user.txt"),
               machine_block_lumma + NL)
        _write(os.path.join(root, "Password.txt"),
               NL.join("%s\t%s\t%s\t%s\t%s" % (u, u.split("//")[-1].split("/")[0], l, p, machine["host"])
                       for u, l, p in cred_rows) + NL)
        _write(os.path.join(root, "Cookies.txt"),
               NL.join("%s\t%s\t%s" % (d, n, v) for d, _, _, _, n, v in cookie_rows) + NL)
        _write(os.path.join(root, "Autofill.txt"), NL.join((
            "email\t%s@example.com" % machine["user"],
            "search\texample query %d" % rng.randint(1, 999),
        )) + NL)
        _write(os.path.join(root, "Processes.txt"), NL.join((
            "explorer.exe", "chrome.exe", "svchost.exe",
        )) + NL)
        _write(os.path.join(root, "Screenshots", "shot_%d.jpg.notes" % rng.randint(1, 9)),
               "synthetic marker file\n")

    else:  # stealc
        _write(os.path.join(root, "vault", "info.txt"), NL.join((
            "Hostname: %s" % machine["host"],
            "Username: %s" % machine["user"],
            "OS: %s" % machine["os"],
            "IP: %s" % machine["ip"],
            "BuildID: %s" % machine["guid"].replace("-", "")[:16].upper(),
        )) + NL)
        browser = rng.choice(BROWSERS)
        _write(os.path.join(root, "vault", "browser", browser, "passwords.txt"),
               NL.join("%s\t%s\t%s" % (u, l, p) for u, l, p in cred_rows) + NL)
        _write(os.path.join(root, "vault", "browser", browser, "cookies.txt"),
               NL.join("%s\t%s\t%s" % (d, n, v) for d, _, _, _, n, v in cookie_rows) + NL)
        _write(os.path.join(root, "vault", "wallets", "phantom", "vault.dat"),
               bytes(rng.getrandbits(8) for _ in range(48)).hex() + NL)
        _write(os.path.join(root, "vault", "telegram", "tdata.marker"), "synthetic\n")

    return root
