"""morgue - local triage for infostealer logs.

Core data model. Everything morgue extracts from a log bundle lands here
before analysis or reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MachineInfo:
    """Victim machine identification pulled from a machine-info artifact."""

    hostname: str = ""
    username: str = ""
    domain: str = ""
    os_name: str = ""
    os_version: str = ""
    guid: str = ""
    external_ip: str = ""
    install_date: str = ""
    language: str = ""
    hardware: str = ""
    build_id: str = ""
    unrecognized_keys: int = 0

    @property
    def identified(self) -> bool:
        return bool(self.hostname or self.username or self.guid)


@dataclass
class Credential:
    """One stolen login record."""

    url: str
    username: str
    password: str
    host: str = ""
    domain: str = ""
    source_file: str = ""


@dataclass
class CookieRecord:
    """One stolen cookie. Values are treated as secrets (masked by default)."""

    domain: str
    name: str
    value: str
    source_file: str = ""


@dataclass
class AutofillEntry:
    """One browser autofill field (form name + stored value)."""

    name: str
    value: str
    source_file: str = ""


@dataclass
class CardRecord:
    """One payment card record. PAN is stored masked, always."""

    masked_pan: str
    expiry: str = ""
    source_file: str = ""


@dataclass
class WalletArtifact:
    """A detected cryptocurrency wallet artifact."""

    name: str
    path: str = ""
    kind: str = "extension"  # extension | desktop | seedfile


@dataclass
class SecretHit:
    """A high-value token found embedded in stolen data (API keys, PATs...)."""

    kind: str
    masked_value: str
    source_file: str = ""


@dataclass
class LogBundle:
    """Parsed content of one victim log (or one generic credential dump)."""

    family: str
    root: str  # relative path of the bundle root, never absolute
    machine: MachineInfo = field(default_factory=MachineInfo)
    credentials: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    autofill: list = field(default_factory=list)
    cards: list = field(default_factory=list)
    wallets: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    artifact_kinds: list = field(default_factory=list)  # e.g. ["telegram", "screenshots"]
    files_seen: int = 0
    warnings: list = field(default_factory=list)

    def merge(self, other: "LogBundle") -> None:
        """Fold another bundle into this one (multi-log directories)."""
        if other.family != "generic":
            self.family = other.family
        if other.machine.identified and not self.machine.identified:
            self.machine = other.machine
        self.credentials.extend(other.credentials)
        self.cookies.extend(other.cookies)
        self.autofill.extend(other.autofill)
        self.cards.extend(other.cards)
        self.wallets.extend(other.wallets)
        self.secrets.extend(other.secrets)
        for kind in other.artifact_kinds:
            if kind not in self.artifact_kinds:
                self.artifact_kinds.append(kind)
        self.files_seen += other.files_seen
        self.warnings.extend(other.warnings)


@dataclass
class DomainCategory:
    """Domain census entry."""

    domain: str
    category: str
    count: int


@dataclass
class SessionCookieFlag:
    """A cookie that grants a live session an attacker could replay."""

    domain: str
    name: str
    reason: str


@dataclass
class PasswordHygiene:
    """Aggregate password hygiene across all credentials in a scan."""

    total: int = 0
    unique: int = 0
    empty: int = 0
    reuse_ratio: float = 0.0
    avg_length: float = 0.0
    min_length: int = 0
    short_count: int = 0  # len < 8
    digits_only: int = 0
    top_reused: list = field(default_factory=list)  # [(masked, count)]


@dataclass
class ScoreReason:
    """One scored contribution to the enterprise exposure score."""

    points: int
    message: str


@dataclass
class ExposureScore:
    """Enterprise exposure score, 0-100, with the reasoning trail."""

    value: int = 0
    band: str = "clean"  # clean | low | medium | high | critical
    reasons: list = field(default_factory=list)


@dataclass
class ScanResult:
    """Top-level result of scanning one path (one or many bundles)."""

    root: str = ""
    family: str = "unknown"
    bundles: list = field(default_factory=list)
    credentials: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    autofill: list = field(default_factory=list)
    cards: list = field(default_factory=list)
    wallets: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    session_flags: list = field(default_factory=list)
    domain_census: list = field(default_factory=list)  # [(domain, category, count)]
    corp_hits: list = field(default_factory=list)  # unique corp domains seen
    hygiene: PasswordHygiene = field(default_factory=PasswordHygiene)
    score: ExposureScore = field(default_factory=ExposureScore)
    warnings: list = field(default_factory=list)
    files_scanned: int = 0

    @property
    def machine_count(self) -> int:
        return len(self.bundles)
