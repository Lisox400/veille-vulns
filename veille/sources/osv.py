"""Source OSV : versions corrigées des paquets open source.

Documentation : https://google.github.io/osv.dev/api/
L'enregistrement CVE d'OSV renvoie vers ses alias (GHSA-…, PYSEC-…, GO-…),
qui portent les plages de versions par paquet et écosystème.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import requests

from ..http import SourceError, build_session, get_json
from ..models import PackageFix
from . import Progress, fetch_each, partial_note

log = logging.getLogger(__name__)

API_URL = "https://api.osv.dev/v1/vulns/"
MAX_ALIASES = 5
# Les plages GIT donnent des commits, pas des versions installables.
_VERSION_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}


@dataclass
class OsvResult:
    fixes: dict[str, list[PackageFix]] = field(default_factory=dict)
    note: str = ""

    def __len__(self) -> int:
        return len(self.fixes)


def fetch_fixes(
    cve_ids: Iterable[str],
    timeout: int = 30,
    workers: int = 8,
    progress: Progress | None = None,
) -> OsvResult:
    ids = list(dict.fromkeys(cve_ids))
    session = build_session()
    fixes, errors = fetch_each("OSV", ids, lambda cve: fetch_one(session, cve, timeout), workers, progress)
    return OsvResult(fixes=fixes, note=partial_note(errors, len(ids)))


def fetch_one(session: requests.Session, cve_id: str, timeout: int) -> list[PackageFix]:
    record = get_json(session, API_URL + cve_id, "OSV", timeout, not_found_ok=True)
    if record is None:
        return []
    records = [record]
    aliases = [a for a in record.get("aliases", []) if not a.startswith("CVE-")][:MAX_ALIASES]
    for alias in aliases:
        try:
            alias_record = get_json(session, API_URL + alias, "OSV", timeout, not_found_ok=True)
        except SourceError as exc:
            log.debug("OSV : alias %s ignoré (%s)", alias, exc)
            continue
        if alias_record:
            records.append(alias_record)
    return merge_fixes(fix for r in records for fix in parse_record(r))


def parse_record(record: dict[str, Any]) -> list[PackageFix]:
    fixes = []
    for affected in record.get("affected", []):
        package = affected.get("package") or {}
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if not ecosystem or not name:
            continue
        fixed = [
            event["fixed"]
            for r in affected.get("ranges", [])
            if r.get("type") in _VERSION_RANGE_TYPES
            for event in r.get("events", [])
            if event.get("fixed")
        ]
        fixes.append(PackageFix(ecosystem, name, tuple(dict.fromkeys(fixed)), (record.get("id", ""),)))
    return fixes


def merge_fixes(fixes: Iterable[PackageFix]) -> list[PackageFix]:
    """Regroupe par (écosystème, paquet) en conservant l'ordre d'apparition."""
    merged: dict[tuple[str, str], PackageFix] = {}
    for fix in fixes:
        key = (fix.ecosystem, fix.package)
        if key in merged:
            prev = merged[key]
            fix = PackageFix(
                fix.ecosystem,
                fix.package,
                tuple(dict.fromkeys(prev.fixed + fix.fixed)),
                tuple(dict.fromkeys(prev.source_ids + fix.source_ids)),
            )
        merged[key] = fix
    return list(merged.values())
