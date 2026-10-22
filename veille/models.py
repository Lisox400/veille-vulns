"""Modèle de données commun à toutes les sources.

Chaque source remplit une partie d'un objet `Vulnerability` ; les sources ne
se connaissent pas entre elles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime


@dataclass(frozen=True)
class CvssInfo:
    version: str          # "3.1", "3.0", "4.0" ou "2.0"
    score: float
    severity: str         # NONE, LOW, MEDIUM, HIGH, CRITICAL
    vector: str
    source: str = ""      # organisme ayant calculé le score
    primary: bool = False  # True si calculé par NVD (type "Primary")


@dataclass(frozen=True)
class Reference:
    url: str
    source: str = ""
    tags: tuple[str, ...] = ()

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags


@dataclass(frozen=True)
class AffectedProduct:
    vendor: str
    product: str
    versions: tuple[str, ...] = ()  # plages lisibles, ex. "≥ 1.2, < 1.4.3"


@dataclass(frozen=True)
class KevEntry:
    """Entrée du catalogue CISA Known Exploited Vulnerabilities."""

    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: date
    short_description: str = ""
    required_action: str = ""
    due_date: date | None = None
    ransomware: bool = False      # knownRansomwareCampaignUse == "Known"
    notes: str = ""
    cwes: tuple[str, ...] = ()


@dataclass(frozen=True)
class EpssScore:
    score: float          # probabilité (0–1) d'exploitation dans les 30 prochains jours
    percentile: float     # rang parmi toutes les CVE notées (0–1)
    date: date | None = None


@dataclass(frozen=True)
class PackageFix:
    """Versions corrigées d'un paquet logiciel, d'après OSV."""

    ecosystem: str                 # PyPI, npm, Maven, Debian:12…
    package: str
    fixed: tuple[str, ...] = ()    # vide = aucune version corrigée connue
    source_ids: tuple[str, ...] = ()  # identifiants OSV (GHSA-…, PYSEC-…)


@dataclass(frozen=True)
class CertFrBulletin:
    """Avis ou alerte du CERT-FR."""

    reference: str                 # CERTFR-2026-AVI-1327
    kind: str                      # "avis" ou "alerte"
    title: str
    url: str
    date: datetime | None = None   # date de la dernière révision
    summary: str = ""
    risks: tuple[str, ...] = ()
    affected_systems: tuple[str, ...] = ()
    solution: str = ""             # sections Solution / Contournement (Markdown)
    vendor_advisories: tuple[tuple[str, str], ...] = ()  # (titre, url)
    cves: tuple[str, ...] = ()


@dataclass(frozen=True)
class CweMitigation:
    phases: tuple[str, ...] = ()      # Architecture and Design, Implementation…
    strategy: str = ""                # Input Validation, Output Encoding…
    description: str = ""
    effectiveness: str = ""           # High, Moderate, Limited…


@dataclass(frozen=True)
class CweConsequence:
    scopes: tuple[str, ...] = ()      # Confidentiality, Integrity…
    impacts: tuple[str, ...] = ()     # Execute Unauthorized Code or Commands…


@dataclass(frozen=True)
class CweInfo:
    """Faiblesse (ou catégorie) du catalogue CWE du MITRE. Contenu en anglais."""

    cwe_id: str                       # "CWE-79"
    name: str
    kind: str = "weakness"            # "weakness" ou "category"
    description: str = ""
    likelihood: str = ""              # probabilité d'exploitation : High, Medium, Low
    consequences: tuple[CweConsequence, ...] = ()
    mitigations: tuple[CweMitigation, ...] = ()
    status: str = ""                  # Stable, Draft, Deprecated…

    @property
    def url(self) -> str:
        return f"https://cwe.mitre.org/data/definitions/{self.cwe_id.removeprefix('CWE-')}.html"


@dataclass
class Vulnerability:
    cve_id: str
    published: datetime | None = None
    last_modified: datetime | None = None
    status: str = ""                      # vulnStatus NVD (Analyzed, Awaiting Analysis…)
    description: str = ""
    cvss: CvssInfo | None = None          # score retenu pour filtrer et trier
    cvss_all: list[CvssInfo] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    cwes: list[CweInfo] = field(default_factory=list)   # détail depuis le catalogue MITRE
    references: list[Reference] = field(default_factory=list)
    affected: list[AffectedProduct] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    affected_source: str = ""             # origine des produits : NVD, CVE.org, CISA KEV
    fixed_versions: list[str] = field(default_factory=list)  # versions corrigées déclarées par le CNA
    kev: KevEntry | None = None
    newly_exploited: bool = False         # ajoutée au KEV pendant la fenêtre analysée
    epss: EpssScore | None = None
    osv_fixes: list[PackageFix] = field(default_factory=list)
    certfr: list[CertFrBulletin] = field(default_factory=list)

    @property
    def cvss_score(self) -> float | None:
        return self.cvss.score if self.cvss else None

    @property
    def is_exploited(self) -> bool:
        return self.kev is not None

    @property
    def has_exploit_reference(self) -> bool:
        return any(r.has_tag("Exploit") for r in self.references)

    @property
    def epss_score(self) -> float | None:
        return self.epss.score if self.epss else None

    @property
    def has_fix(self) -> bool:
        """Un correctif est attesté par au moins une source."""
        return (
            any(r.has_tag("Patch") for r in self.references)
            or any(f.fixed for f in self.osv_fixes)
            or bool(self.fixed_versions)
            or any(b.solution for b in self.certfr)
        )


@dataclass
class SourceStatus:
    """État d'une source après interrogation, affiché dans le rapport."""

    name: str
    ok: bool
    message: str = ""
    count: int = 0
    duration: float = 0.0


def severity_from_score(score: float) -> str:
    """Sévérité qualitative CVSS v3/v4 à partir du score de base."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"
