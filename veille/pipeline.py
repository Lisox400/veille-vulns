"""Orchestration d'un lancement : interrogation des sources, fusion, sélection
des nouveautés et mise à jour du cache."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, time, timezone

from .cache import Cache
from .config import Config
from .models import AffectedProduct, KevEntry, SourceStatus, Vulnerability
from .sources import Progress, run_source
from .sources import certfr, cveorg, cwe, epss, osv
from .sources.cisa_kev import fetch_catalog
from .sources.nvd import NvdClient

log = logging.getLogger(__name__)


@dataclass
class RunResult:
    window_start: datetime
    window_end: datetime
    fetched: list[Vulnerability] = field(default_factory=list)  # tout ce qui a été récupéré
    statuses: list[SourceStatus] = field(default_factory=list)
    nvd_ok: bool = False
    kev_ok: bool = False

    def status(self, name: str) -> SourceStatus | None:
        return next((s for s in self.statuses if s.name == name), None)


def collect(config: Config, start: datetime, end: datetime) -> RunResult:
    result = RunResult(window_start=start, window_end=end)
    timeout = config.general.timeout

    nvd = NvdClient(timeout=timeout)
    published, nvd_status = run_source("NVD", lambda: nvd.fetch_published(start, end))
    result.statuses.append(nvd_status)
    result.nvd_ok = nvd_status.ok
    by_id = {v.cve_id: v for v in published or []}

    catalog, kev_status = run_source("CISA KEV", lambda: fetch_catalog(config.general.data_dir, timeout))
    result.statuses.append(kev_status)
    result.kev_ok = kev_status.ok
    if catalog is not None:
        # Le KEV est daté au jour : on prend tout le jour de début de fenêtre,
        # les doublons éventuels sont écartés grâce au cache.
        kev_day = start.astimezone(timezone.utc).date()
        added = list(catalog.added_since(kev_day))
        missing = [e for e in added if e.cve_id not in by_id]

        if missing and nvd_status.ok:
            kev_start = datetime.combine(kev_day, time.min, tzinfo=timezone.utc)
            extra, extra_status = run_source(
                "NVD (ajouts KEV)", lambda: nvd.fetch_kev_added(kev_start, end)
            )
            if not extra_status.ok:
                result.statuses.append(extra_status)
            for v in extra or []:
                by_id.setdefault(v.cve_id, v)

        for entry in added:
            if entry.cve_id not in by_id:
                log.info("%s absente de NVD : données KEV seules", entry.cve_id)
                by_id[entry.cve_id] = vulnerability_from_kev(entry)

        for v in by_id.values():
            v.kev = catalog.get(v.cve_id)
            if v.kev and not v.cwe_ids:
                v.cwe_ids = list(v.kev.cwes)
            v.newly_exploited = v.kev is not None and v.kev.date_added >= kev_day

    result.fetched = list(by_id.values())
    return result


def select_new(result: RunResult, cache: Cache, show_seen: bool = False) -> list[Vulnerability]:
    """CVE jamais vues, plus celles déjà vues mais devenues exploitées depuis."""
    if show_seen:
        return list(result.fetched)
    ids = [v.cve_id for v in result.fetched]
    seen = cache.seen_ids(ids)
    seen_kev = cache.seen_kev_ids(ids)
    return [
        v for v in result.fetched
        if v.cve_id not in seen or (v.newly_exploited and v.cve_id not in seen_kev)
    ]


def commit(cache: Cache, result: RunResult, started: datetime, new_count: int) -> None:
    if result.nvd_ok:
        cache.mark_seen(result.fetched, started)
    if result.kev_ok:
        cache.mark_kev_seen((v for v in result.fetched if v.newly_exploited), started)
    # Un échec NVD n'avance pas la fenêtre : le prochain lancement reprendra au même point.
    cache.record_run(started, result.window_start, result.window_end, result.nvd_ok, new_count)


def enrich(
    config: Config,
    vulns: list[Vulnerability],
    statuses: list[SourceStatus],
    progress: Progress | None = None,
    force_cveorg: bool = False,
) -> None:
    """Complète les CVE avec EPSS, CERT-FR, CVE.org et OSV (statuts ajoutés à `statuses`).

    N'est appelé que sur les CVE à afficher : OSV et CVE.org sont interrogés
    CVE par CVE, inutile de le faire pour celles déjà vues.
    """
    if not vulns:
        return
    sources, timeout, workers = config.sources, config.general.timeout, config.sources.workers
    ids = [v.cve_id for v in vulns]

    if sources.epss:
        scores, status = run_source("EPSS", lambda: epss.fetch_scores(ids, timeout))
        statuses.append(status)
        for v in vulns:
            v.epss = scores.scores.get(v.cve_id) if scores else None

    if sources.certfr:
        bulletins, status = run_source(
            "CERT-FR",
            lambda: certfr.fetch_bulletins(config.general.data_dir, timeout, min(workers, 4), progress),
        )
        statuses.append(status)
        index = bulletins.by_cve() if bulletins else {}
        for v in vulns:
            v.certfr = index.get(v.cve_id, [])

    if sources.cveorg:
        # Seulement quand NVD n'a pas de CPE, sauf demande explicite (fiche détaillée).
        # Toujours pour les failles exploitées (peu nombreuses) : versions corrigées déclarées par le CNA.
        targets = [
            v for v in vulns
            if force_cveorg or v.is_exploited or not v.affected or v.affected_source == "CISA KEV"
        ]
        if targets:
            records, status = run_source(
                "CVE.org",
                lambda: cveorg.fetch_records([v.cve_id for v in targets], timeout, min(workers, 4), progress),
            )
            statuses.append(status)
            for v in targets:
                record = records.records.get(v.cve_id) if records else None
                if not record:
                    continue
                if record.affected and (not v.affected or v.affected_source == "CISA KEV"):
                    v.affected = record.affected
                    v.affected_source = "CVE.org (CNA)"
                v.fixed_versions = record.fixed_versions

    if sources.osv:
        fixes, status = run_source("OSV", lambda: osv.fetch_fixes(ids, timeout, workers, progress))
        statuses.append(status)
        for v in vulns:
            v.osv_fixes = fixes.fixes.get(v.cve_id, []) if fixes else []

    if sources.cwe:
        catalog, status = run_source(
            "CWE MITRE", lambda: cwe.fetch_catalog(config.general.data_dir, max(timeout, 60))
        )
        statuses.append(status)
        if catalog:
            for v in vulns:
                v.cwes = [info for cwe_id in v.cwe_ids if (info := catalog.get(cwe_id))]


def vulnerability_from_kev(entry: KevEntry) -> Vulnerability:
    """Repli quand NVD ne renvoie pas la CVE (indisponible ou pas encore indexée)."""
    return Vulnerability(
        cve_id=entry.cve_id,
        status="Données CISA KEV uniquement",
        description=entry.short_description,
        cwe_ids=list(entry.cwes),
        affected=[AffectedProduct(vendor=entry.vendor, product=entry.product)],
        affected_source="CISA KEV",
    )
