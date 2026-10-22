"""Opérations de haut niveau, partagées par les sous-commandes et le menu interactif.

Aucun affichage ici : chaque méthode renvoie des données ou lève `SourceError`.
Les catalogues (KEV, CWE, CERT-FR) sont chargés une fois par session.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import pipeline
from .cache import Cache
from .config import Config, FilterConfig
from .filtering import FilterOutcome, apply_filters, describe, prefilter, prioritize
from .http import SourceError
from .models import CertFrBulletin, EpssScore, KevEntry, SourceStatus, Vulnerability
from .report.builder import build_report, write_report
from .sources import Progress, run_source
from .sources.certfr import CertFrResult, fetch_bulletins
from .sources.cisa_kev import KevCatalog, fetch_catalog
from .sources.cwe import CweCatalog
from .sources.cwe import fetch_catalog as fetch_cwe_catalog
from .sources.epss import fetch_scores
from .sources.nvd import NvdClient

_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def parse_since(value: str, now: datetime) -> datetime:
    if m := re.fullmatch(r"(\d+)\s*([hd])", value.strip().lower()):
        amount, unit = int(m.group(1)), m.group(2)
        return now - (timedelta(hours=amount) if unit == "h" else timedelta(days=amount))
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        raise ValueError(f"fenêtre invalide : {value!r} (attendu : 48h, 7d ou 2026-10-01)") from None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize_ids(values: list[str]) -> list[str]:
    ids = []
    for value in values:
        if not _CVE_ID.fullmatch(value.strip()):
            raise ValueError(f"identifiant invalide : {value!r} (attendu : CVE-AAAA-NNNN)")
        ids.append(value.strip().upper())
    return list(dict.fromkeys(ids))


@dataclass
class ScanRun:
    start: datetime
    end: datetime
    result: pipeline.RunResult
    new_count: int
    outcome: FilterOutcome
    filters: list[str] = field(default_factory=list)

    @property
    def statuses(self) -> list[SourceStatus]:
        return self.result.statuses


class Toolkit:
    def __init__(self, config: Config, progress: Progress | None = None) -> None:
        self.config = config
        self.progress = progress
        self._nvd: NvdClient | None = None
        self._kev: KevCatalog | None = None
        self._cwe: CweCatalog | None = None
        self._certfr: CertFrResult | None = None
        self.last_scan: ScanRun | None = None
        self.last_reports: list[Path] = []

    # --- Catalogues chargés une fois par session ----------------------------------------

    @property
    def nvd(self) -> NvdClient:
        if self._nvd is None:
            self._nvd = NvdClient(timeout=self.config.general.timeout)
        return self._nvd

    def kev_catalog(self) -> KevCatalog:
        if self._kev is None:
            self._kev = _required(run_source(
                "CISA KEV", lambda: fetch_catalog(self.config.general.data_dir, self.config.general.timeout)))
        return self._kev

    def cwe_catalog(self) -> CweCatalog:
        if self._cwe is None:
            self._cwe = _required(run_source(
                "CWE MITRE", lambda: fetch_cwe_catalog(self.config.general.data_dir)))
        return self._cwe

    def certfr(self) -> CertFrResult:
        if self._certfr is None:
            self._certfr = _required(run_source("CERT-FR", lambda: fetch_bulletins(
                self.config.general.data_dir, self.config.general.timeout, progress=self.progress)))
        return self._certfr

    # --- Scan -------------------------------------------------------------------------------

    def scan_window(self, since: str | None) -> tuple[datetime, datetime]:
        end = datetime.now(timezone.utc).replace(microsecond=0)
        if since:
            return parse_since(since, end), end
        with Cache(self.config.general.data_dir / "veille.db") as cache:
            last = cache.last_window_end()
        if last is not None:
            # Recouvrement : NVD indexe parfois des CVE avec un léger retard.
            return last - timedelta(hours=self.config.general.overlap_hours), end
        return end - timedelta(hours=self.config.general.first_run_hours), end

    def scan(
        self,
        start: datetime,
        end: datetime,
        filters: FilterConfig | None = None,
        show_seen: bool = False,
        dry_run: bool = False,
        enrich: bool = True,
    ) -> ScanRun:
        filters = filters or self.config.filters
        with Cache(self.config.general.data_dir / "veille.db") as cache:
            result = pipeline.collect(self.config, start, end)
            new = pipeline.select_new(result, cache, show_seen)
            # Filtres CVSS/KEV avant l'enrichissement (moins de requêtes), mots-clés après.
            candidates, excluded = prefilter(new, filters)
            if enrich:
                pipeline.enrich(self.config, candidates, result.statuses, self.progress)
            outcome = apply_filters(candidates, filters, excluded)
            if not dry_run:
                # Toutes les nouvelles CVE sont marquées vues, y compris celles écartées par les filtres.
                pipeline.commit(cache, result, end, len(outcome.all))
        self.last_scan = ScanRun(start, end, result, len(new), outcome, describe(filters))
        return self.last_scan

    def scan_report(self, run: ScanRun, formats: tuple[str, ...] = ("md", "html"),
                    output: Path | None = None) -> list[Path]:
        report = build_report(run.outcome, run.statuses, run.filters, run.start, run.end,
                              len(run.result.fetched), run.new_count, run.end)
        self.last_reports = write_report(report, output or self.config.general.reports_dir, formats)
        return self.last_reports

    # --- Recherches ponctuelles ----------------------------------------------------------------

    def lookup(self, ids: list[str]) -> tuple[list[Vulnerability], list[SourceStatus]]:
        """Fiches complètes (toutes sources) pour des identifiants CVE."""
        statuses: list[SourceStatus] = []
        vulns: list[Vulnerability] = []
        for cve_id in ids:
            found, status = run_source("NVD", lambda: self.nvd.fetch_by_id(cve_id))
            if not status.ok:
                statuses.append(status)
            vulns.append(found or Vulnerability(cve_id, status="introuvable dans NVD" if status.ok else ""))
        try:
            catalog = self.kev_catalog()
        except SourceError as exc:
            statuses.append(SourceStatus("CISA KEV", ok=False, message=str(exc)))
            catalog = None
        if catalog:
            for i, v in enumerate(vulns):
                kev = catalog.get(v.cve_id)
                if kev and not v.description:
                    vulns[i] = pipeline.vulnerability_from_kev(kev)
                vulns[i].kev = kev
                if kev and not vulns[i].cwe_ids:
                    vulns[i].cwe_ids = list(kev.cwes)
        pipeline.enrich(self.config, vulns, statuses, self.progress, force_cveorg=True)
        return vulns, statuses

    def lookup_report(self, vulns: list[Vulnerability], statuses: list[SourceStatus],
                      formats: tuple[str, ...] = ("md", "html"), output: Path | None = None) -> list[Path]:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        outcome = FilterOutcome(
            kept=prioritize([v for v in vulns if v.cvss]), unscored=prioritize([v for v in vulns if not v.cvss])
        )
        ids = ", ".join(v.cve_id for v in vulns)
        report = build_report(outcome, statuses, [f"fiches demandées : {ids}"], now, now, len(vulns), len(vulns), now)
        self.last_reports = write_report(report, output or self.config.general.reports_dir, formats)
        return self.last_reports

    def kev_recent(self, days: int, ransomware: bool = False,
                   grep: str | None = None) -> tuple[list[KevEntry], dict[str, EpssScore]]:
        catalog = self.kev_catalog()
        since = (datetime.now(timezone.utc) - timedelta(days=days)).date()
        entries = [e for e in catalog.added_since(since) if not ransomware or e.ransomware]
        if grep:
            needle = grep.lower()
            entries = [e for e in entries if needle in f"{e.vendor} {e.product} {e.name} {e.cve_id}".lower()]
        entries.sort(key=lambda e: (e.date_added, e.cve_id), reverse=True)
        return entries, self.epss([e.cve_id for e in entries]) if entries else {}

    def certfr_recent(self, days: int, alertes: bool = False, grep: str | None = None) -> list[CertFrBulletin]:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        bulletins = [b for b in self.certfr().bulletins if b.date and b.date >= since]
        if alertes:
            bulletins = [b for b in bulletins if b.kind == "alerte"]
        if grep:
            needle = grep.lower()
            bulletins = [b for b in bulletins if needle in " ".join((b.title, *b.affected_systems)).lower()]
        return bulletins

    def epss(self, ids: list[str]) -> dict[str, EpssScore]:
        if not ids or not self.config.sources.epss:
            return {}
        result, _ = run_source("EPSS", lambda: fetch_scores(ids, self.config.general.timeout))
        return result.scores if result else {}

    @property
    def kev_note(self) -> str:
        return self._kev.note if self._kev else ""


def _required(outcome):
    value, status = outcome
    if value is None:
        raise SourceError(f"{status.name} indisponible : {status.message}")
    return value
