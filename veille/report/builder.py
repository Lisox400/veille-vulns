"""Construction du rapport : un modèle commun, rendu en Markdown et en HTML."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..enrichment import cvss
from ..enrichment import cwe as cwe_fr
from ..filtering import FilterOutcome
from ..models import SourceStatus, Vulnerability
from .text import paragraphs, shorten, solution_paragraphs

SEVERITY_FR = {"CRITICAL": "Critique", "HIGH": "Élevée", "MEDIUM": "Moyenne", "LOW": "Faible", "NONE": "Aucune"}


@dataclass
class CweView:
    cwe_id: str
    name: str
    url: str
    summary: str
    consequences: list[str]
    likelihood: str
    prevention: list[tuple[str, str]]  # (libellé, texte) ; texte complet dans l'annexe


@dataclass
class CertFrView:
    reference: str
    kind: str
    url: str
    title: str
    date: str
    affected_systems: list[str]
    solution: list[str]                 # paragraphes
    vendor_advisories: list[tuple[str, str]]


@dataclass
class VulnView:
    rank: int
    cve_id: str
    anchor: str
    published: str
    severity: str                       # CRITICAL, HIGH… ou "" si non noté
    cvss_label: str                     # "9.8 · Critique · CVSS 3.1"
    cvss_vector: str
    epss_label: str
    epss: float | None
    products: list[str]
    products_source: str
    description: str
    nvd_status: str
    explanation: cvss.CvssExplanation | None
    exploited: bool
    kev_label: str
    ransomware: bool
    exploit_reference: bool
    cwes: list[CweView]
    patches: list[str]
    advisories: list[str]
    mitigations: list[str]
    cna_fixes: list[str]
    osv_fixes: list[str]
    kev_action: str
    certfr: list[CertFrView]
    has_fix: bool
    unscored: bool = False

    @property
    def short_product(self) -> str:
        return self.products[0].split(" : ")[0] if self.products else "non renseigné"


@dataclass
class ReportData:
    generated_at: datetime
    window_start: datetime
    window_end: datetime
    statuses: list[SourceStatus]
    filters: list[str]
    total_fetched: int
    new_count: int
    excluded: dict[str, int]
    vulns: list[VulnView] = field(default_factory=list)
    unscored: list[VulnView] = field(default_factory=list)
    appendix: list[tuple[CweView, int]] = field(default_factory=list)  # (CWE, nombre de failles)

    @property
    def all(self) -> list[VulnView]:
        return self.vulns + self.unscored

    @property
    def critical(self) -> int:
        return sum(v.severity == "CRITICAL" for v in self.all)

    @property
    def exploited(self) -> int:
        return sum(v.exploited for v in self.all)

    @property
    def ransomware(self) -> int:
        return sum(v.ransomware for v in self.all)

    @property
    def without_fix(self) -> int:
        return sum(not v.has_fix for v in self.all)

    @property
    def excluded_count(self) -> int:
        return sum(self.excluded.values())


def build_report(
    outcome: FilterOutcome,
    statuses: list[SourceStatus],
    filters: list[str],
    window_start: datetime,
    window_end: datetime,
    total_fetched: int,
    new_count: int,
    generated_at: datetime,
) -> ReportData:
    data = ReportData(
        generated_at=generated_at,
        window_start=window_start,
        window_end=window_end,
        statuses=statuses,
        filters=filters,
        total_fetched=total_fetched,
        new_count=new_count,
        excluded=dict(outcome.excluded.most_common()),
    )
    data.vulns = [vuln_view(v, rank) for rank, v in enumerate(outcome.kept, 1)]
    offset = len(data.vulns)
    data.unscored = [vuln_view(v, offset + rank, unscored=True) for rank, v in enumerate(outcome.unscored, 1)]

    # Annexe : chaque CWE rencontrée une seule fois, avec ses mesures de prévention
    # complètes, au lieu de les recopier dans chaque fiche.
    counts: dict[str, int] = {}
    infos = {}
    for v in outcome.all:
        for info in v.cwes:
            counts[info.cwe_id] = counts.get(info.cwe_id, 0) + 1
            infos[info.cwe_id] = info
    data.appendix = [
        (_cwe_view(infos[cwe_id], mitigations=5, text_size=700), count)
        for cwe_id, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    return data


def vuln_view(v: Vulnerability, rank: int, unscored: bool = False) -> VulnView:
    refs_with = lambda tag: list(dict.fromkeys(r.url for r in v.references if r.has_tag(tag)))  # noqa: E731
    patches = refs_with("Patch")
    advisories = [u for u in refs_with("Vendor Advisory") if u not in patches]
    mitigations = [u for u in refs_with("Mitigation") if u not in patches and u not in advisories]

    if v.cvss:
        severity = v.cvss.severity
        cvss_label = f"{v.cvss.score:.1f} · {SEVERITY_FR.get(severity, severity)} · CVSS {v.cvss.version}"
    else:
        severity, cvss_label = "", "pas encore noté"
    if v.epss:
        epss_label = f"{v.epss.score * 100:.1f} % (percentile {v.epss.percentile * 100:.0f})"
    else:
        epss_label = "n/a"

    kev_label = ""
    if v.kev:
        kev_label = f"ajoutée au catalogue le {v.kev.date_added:%d/%m/%Y}"
        if v.kev.due_date:
            kev_label += f", échéance de correction CISA le {v.kev.due_date:%d/%m/%Y}"

    return VulnView(
        rank=rank,
        cve_id=v.cve_id,
        anchor=v.cve_id.lower(),
        published=f"{v.published:%d/%m/%Y}" if v.published else "inconnue",
        severity=severity,
        cvss_label=cvss_label,
        cvss_vector=v.cvss.vector if v.cvss else "",
        epss_label=epss_label,
        epss=v.epss_score,
        products=[
            f"{a.vendor} / {a.product}" + (f" : {' ; '.join(a.versions)}" if a.versions else "")
            for a in v.affected
        ],
        products_source=v.affected_source,
        description=v.description,
        nvd_status=v.status,
        explanation=cvss.explain(v.cvss.vector) if v.cvss else None,
        exploited=v.is_exploited,
        kev_label=kev_label,
        ransomware=bool(v.kev and v.kev.ransomware),
        exploit_reference=v.has_exploit_reference,
        cwes=[_cwe_view(info) for info in v.cwes] or [
            CweView(cwe_id, "", f"https://cwe.mitre.org/data/definitions/{cwe_id.removeprefix('CWE-')}.html",
                    "", [], "", [])
            for cwe_id in v.cwe_ids
        ],
        patches=patches,
        advisories=advisories,
        mitigations=mitigations,
        cna_fixes=list(v.fixed_versions),
        osv_fixes=[
            f"[{f.ecosystem}] {f.package} : " + (", ".join(f.fixed) if f.fixed else "aucune version corrigée")
            for f in v.osv_fixes
        ],
        kev_action=v.kev.required_action if v.kev else "",
        certfr=[
            CertFrView(
                reference=b.reference,
                kind=b.kind,
                url=b.url,
                title=b.title,
                date=f"{b.date:%d/%m/%Y}" if b.date else "",
                affected_systems=list(b.affected_systems),
                solution=solution_paragraphs(b.solution) if b.solution else [],
                vendor_advisories=list(b.vendor_advisories),
            )
            for b in v.certfr
        ],
        has_fix=v.has_fix,
        unscored=unscored,
    )


def _cwe_view(info, mitigations: int = 3, text_size: int = 0) -> CweView:
    return CweView(
        cwe_id=info.cwe_id,
        name=info.name,
        url=info.url,
        summary=shorten(paragraphs(info.description)[0], 400) if info.description else "",
        consequences=cwe_fr.consequences_fr(info, 4),
        likelihood=cwe_fr.likelihood_fr(info) if info.likelihood else "",
        prevention=[
            (cwe_fr.mitigation_label(m) or "Mesure", shorten(m.description, text_size) if text_size else "")
            for m in cwe_fr.top_mitigations(info, mitigations)
        ],
    )


def write_report(data: ReportData, reports_dir: Path, formats: tuple[str, ...] = ("md", "html")) -> list[Path]:
    from . import html, markdown

    reports_dir.mkdir(parents=True, exist_ok=True)
    stem = f"veille_{data.generated_at:%Y-%m-%d_%H%M}"
    renderers = {"md": markdown.render, "html": html.render}
    written = []
    for fmt in formats:
        path = reports_dir / f"{stem}.{fmt}"
        path.write_text(renderers[fmt](data), encoding="utf-8")
        written.append(path)
    return written
