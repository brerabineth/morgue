"""Line-level parsers for stealer log artifacts.

Stealer logs converge on a handful of tab-separated line shapes. Rather than
one brittle parser per family, morgue parses the shapes:

  credentials: url[TAB login][TAB password][TAB ...extra columns]
  cookies:     netscape 7-col | 5-col flag | 4-col path | 3-col d/n/v
  autofill:    name[TAB value]
  cards:       pan[TAB expiry][TAB ...]        (PAN masked on parse, always)
  machine:     "Key: value" text or flat JSON

Unknown shapes are skipped and counted as warnings. Nothing here raises on
malformed input; log files are crime scenes, not source code.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from .models import AutofillEntry, CardRecord, CookieRecord, Credential, MachineInfo

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_HOST_RE = re.compile(r"^[A-Za-z0-9._\-]{1,253}(:\d{1,5})?$")

# two-part public suffixes that must keep three labels for a "registrable" view
_MULTIPART_SUFFIXES = frozenset(
    (
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp", "co.nz", "com.br", "com.mx", "com.ar",
        "com.tr", "com.cn", "com.hk", "com.sg", "com.ua", "co.za", "com.pl",
        "com.es", "com.pt", "com.gr", "com.sa", "com.eg", "co.in", "co.id",
    )
)

MACHINE_TEXT_KEYS = (
    ("hostname", re.compile(r"^(?:Computer name|Hostname|Host)\s*:\s*(.+)$", re.I | re.M)),
    ("username", re.compile(r"^(?:User(?: ?name)?|Windows user|User Name)\s*:\s*(.+)$", re.I | re.M)),
    ("domain", re.compile(r"^Domain\s*:\s*(.+)$", re.I | re.M)),
    ("os_name", re.compile(r"^(?:OS|Operating System)\s*:\s*(.+)$", re.I | re.M)),
    ("os_version", re.compile(r"^(?:OS version|Version|OS Version)\s*:\s*(.+)$", re.I | re.M)),
    ("guid", re.compile(r"^(?:Global ID|GUID|Machine GUID|Bot ?ID|BotID)\s*:\s*[{\[]?([0-9A-Fa-f\-]{8,})[}\]]?\s*$", re.I | re.M)),
    ("external_ip", re.compile(r"^(?:IP|External IP|IP address)\s*:\s*([0-9a-fA-F.:%]{7,45})$", re.I | re.M)),
    ("install_date", re.compile(r"^(?:Install(?:ation)? date|Installed)\s*:\s*(.+)$", re.I | re.M)),
    ("language", re.compile(r"^(?:System language|Language|Lang)\s*:\s*(.+)$", re.I | re.M)),
    ("hardware", re.compile(r"^(?:CPU|RAM|Hardware)\s*:\s*(.+)$", re.I | re.M)),
    ("build_id", re.compile(r"^(?:Build ?ID|Build)\s*:\s*(.+)$", re.I | re.M)),
)

_MACHINE_JSON_KEYS = {
    "hostname": ("hostname", "computer_name", "computername", "host"),
    "username": ("username", "user", "user_name", "windows_user"),
    "domain": ("domain", "workgroup"),
    "os_name": ("os", "operating_system", "os_name"),
    "os_version": ("os_version", "version", "os_build"),
    "guid": ("guid", "global_id", "machine_guid", "botid", "bot_id"),
    "external_ip": ("ip", "external_ip", "ip_address", "wan_ip"),
    "build_id": ("buildid", "build_id", "build"),
}


def looks_like_url(value: str) -> bool:
    """True when a field is a URL (scheme required)."""
    return bool(value) and bool(_SCHEME_RE.match(value))


def looks_like_host(value: str) -> bool:
    """True when a bare field is a hostname[:port]."""
    if not value or looks_like_url(value) or value.startswith("@"):
        return False
    return bool(_HOST_RE.match(value)) and "." in value


def host_of(url: str) -> str:
    """Extract host[:port] from a URL string; empty when no scheme/garbage."""
    try:
        stripped = url.strip()
        if not _SCHEME_RE.match(stripped):
            return ""
        rest = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", stripped, flags=re.IGNORECASE)
        rest = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in rest:  # strip userinfo
            rest = rest.rsplit("@", 1)[1]
        host = rest.lower().rstrip(".")
        return host if host else ""
    except Exception:
        return ""


def domain_of(host: str) -> str:
    """Crude registrable domain: last two labels (three for known suffixes)."""
    if not host:
        return ""
    host = host.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTIPART_SUFFIXES:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def _clean_field(raw: str) -> str:
    return raw.strip().strip('"').strip()


def parse_credential_line(line: str, source_file: str = "") -> Optional[Credential]:
    """Parse one credential row. Handles 3-col (url/login/pass) and
    4+ col (url/host/login/pass/...) shapes."""
    cols = [c.strip() for c in line.split("\t")]
    if len(cols) < 3:
        return None
    url, login, password = cols[0], "", ""
    if len(cols) >= 4 and looks_like_host(cols[1]):
        login, password = cols[2], cols[3]
    else:
        login, password = cols[1], cols[2]
    if not looks_like_url(url) or not login:
        return None
    if any(ch.isspace() for ch in login):
        return None  # logins never contain spaces; titles do
    if login.startswith("[") and login.endswith("]"):  # some panels bracket logins
        login = login[1:-1]
    host = host_of(url)
    return Credential(
        url=url,
        username=login,
        password=password,
        host=host,
        domain=domain_of(host),
        source_file=source_file,
    )


def parse_cookie_line(line: str, source_file: str = "") -> Optional[CookieRecord]:
    """Parse one cookie row in any of the common shapes.

    Supported: netscape 7-col and 6-col (flag in col 1, name/value last two),
    5-col flag variant, 4-col path variant, plain 3-col d/n/v.
    """
    cols = [c.strip() for c in line.split("\t")]
    n = len(cols)
    if n >= 6 and cols[1].upper() in ("TRUE", "FALSE"):  # netscape (6 or 7 col)
        domain, name, value = cols[0], cols[-2], cols[-1]
    elif n == 5 and cols[1].upper() in ("TRUE", "FALSE"):
        domain, name, value = cols[0], cols[3], cols[4]
    elif n == 4 and cols[1].startswith("/"):
        domain, name, value = cols[0], cols[2], cols[3]
    elif n >= 3:
        domain, name, value = cols[0], cols[1], cols[2]
    else:
        return None
    if not domain or not name or domain.startswith("#"):
        return None
    domain = domain.lstrip(".").lower()
    if not domain:
        return None
    return CookieRecord(domain=domain, name=name, value=value, source_file=source_file)


def parse_autofill_line(line: str, source_file: str = "") -> Optional[AutofillEntry]:
    cols = [c.strip() for c in line.split("\t")]
    if len(cols) < 2 or not cols[0]:
        return None
    return AutofillEntry(name=cols[0], value=cols[1], source_file=source_file)


def mask_pan(pan: str) -> str:
    digits = re.sub(r"\D", "", pan)
    if len(digits) < 8:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def parse_card_line(line: str, source_file: str = "") -> Optional[CardRecord]:
    cols = [c.strip() for c in line.split("\t")]
    if len(cols) < 1:
        return None
    digits = re.sub(r"[\s\-]", "", cols[0])
    if not re.fullmatch(r"[0-9]{12,19}", digits):
        return None
    expiry = ""
    for col in cols[1:3]:
        if re.fullmatch(r"\d{2}/\d{2,4}", col):
            expiry = col
            break
    return CardRecord(masked_pan=mask_pan(digits), expiry=expiry, source_file=source_file)


def parse_machine_text(text: str) -> MachineInfo:
    """Parse a 'Key: value' style machine info artifact."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    info = MachineInfo()
    seen = set()
    for field_name, rx in MACHINE_TEXT_KEYS:
        match = rx.search(text)
        if match:
            value = _clean_field(match.group(1))
            setattr(info, field_name, value[:200])
            seen.add(match.group(0).split(":", 1)[0].strip().lower())
    key_lines = re.findall(r"^([A-Za-z][A-Za-z0-9 _./-]{1,40})\s*:", text, re.M)
    info.unrecognized_keys = sum(1 for k in key_lines if k.strip().lower() not in seen)
    return info


def parse_machine_json(data) -> MachineInfo:
    """Parse a flat JSON machine info artifact (StealC style)."""
    info = MachineInfo()
    if not isinstance(data, dict):
        return info
    lower_map = {str(k).lower(): v for k, v in data.items()}
    matched = 0
    for field_name, aliases in _MACHINE_JSON_KEYS.items():
        for alias in aliases:
            if alias in lower_map and isinstance(lower_map[alias], (str, int)):
                value = str(lower_map[alias]).strip()
                if value:
                    setattr(info, field_name, value[:200])
                    matched += 1
                    break
    info.unrecognized_keys = max(0, len(data) - matched)
    return info


def parse_machine_auto(text: str) -> MachineInfo:
    """Try JSON first, fall back to 'Key: value' text."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            return parse_machine_json(json.loads(stripped))
        except (ValueError, TypeError):
            pass
    return parse_machine_text(text)
