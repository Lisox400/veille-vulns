"""Source CVE.org (API CVE Services) : produits et versions déclarés par le CNA.

Documentation : https://cveawg.mitre.org/api-docs/
Utilisée quand NVD n'a pas encore ajouté de CPE (cas de la plupart des CVE
récentes). Fournit aussi les versions corrigées quand le CNA les déclare.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import requests

from ..http import build_session, get_json
from ..models import AffectedProduct
from . import Progress, fetch_each, partial_note

API_URL = "https://cveawg.mitre.org/api/cve/"
_UNSPECIFIED = {"", "*", "0", "n/a", "unspecified", "-"}


@dataclass(frozen=True)
class CveOrgRecord:
    affected: list[AffectedProduct] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)  # "Produit : version"


@dataclass
class CveOrgResult:
    records: dict[str, CveOrgRecord] = field(default_factory=dict)
    note: str = ""

    def __len__(self) -> int:
        return len(self.records)


def fetch_records(
    cve_ids: Iterable[str],
    timeout: int = 30,
    workers: int = 4,
    progress: Progress | None = None,
) -> CveOrgResult:
    ids = list(dict.fromkeys(cve_ids))
    session = build_session()
    records, errors = fetch_each("CVE.org", ids, lambda cve: fetch_one(session, cve, timeout), workers, progress)
    return CveOrgResult(records=records, note=partial_note(errors, len(ids)))


def fetch_one(session: requests.Session, cve_id: str, timeout: int) -> CveOrgRecord | None:
    data = get_json(session, API_URL + cve_id, "CVE.org", timeout, not_found_ok=True)
    if not data:
        return None
    record = parse_record(data)
    return record if record.affected or record.fixed_versions else None


def parse_record(data: dict[str, Any]) -> CveOrgRecord:
    containers = data.get("containers", {})
    record = _parse_affected(containers.get("cna", {}).get("affected", []))
    if not record.affected:
        # Repli sur les ADP (ex. CISA-ADP « Vulnrichment ») qui complètent parfois le CNA.
        for adp in containers.get("adp", []):
            record = _parse_affected(adp.get("affected", []))
            if record.affected:
                break
    return record


def _parse_affected(items: list[dict[str, Any]]) -> CveOrgRecord:
    products: list[AffectedProduct] = []
    fixed: list[str] = []
    for item in items:
        vendor = (item.get("vendor") or "").strip()
        product = (item.get("product") or item.get("packageName") or "").strip()
        if vendor.lower() in _UNSPECIFIED and product.lower() in _UNSPECIFIED:
            continue
        labels: list[str] = []
        for version in item.get("versions", []):
            if version.get("status") != "affected" or version.get("versionType") == "git":
                continue
            label = version_label(version)
            if label not in labels:
                labels.append(label)
            # Version corrigée : point de changement explicite, sinon borne
            # exclusive de la plage affectée (« affecté avant 1.6.20 »).
            fixed_at = [c["at"] for c in version.get("changes", []) if c.get("status") == "unaffected" and c.get("at")]
            less_than = str(version.get("lessThan", "")).strip()
            if not fixed_at and less_than and less_than != "*" and item.get("defaultStatus") != "affected":
                fixed_at = [less_than]
            for at in fixed_at:
                entry = f"{product or vendor} : {at}"
                if entry not in fixed:
                    fixed.append(entry)
        if not labels and item.get("defaultStatus") == "affected":
            labels.append("toutes versions")
        products.append(AffectedProduct(vendor=vendor or "?", product=product or "?", versions=tuple(labels)))
    return CveOrgRecord(affected=products, fixed_versions=fixed)


def version_label(version: dict[str, Any]) -> str:
    start = str(version.get("version", "")).strip()
    less_than = str(version.get("lessThan", "")).strip()
    less_equal = str(version.get("lessThanOrEqual", "")).strip()
    has_start = start.lower() not in _UNSPECIFIED
    if less_than or less_equal:
        bounds = [f"≥ {start}"] if has_start else []
        if less_than and less_than != "*":
            bounds.append(f"< {less_than}")
        elif less_equal and less_equal != "*":
            bounds.append(f"≤ {less_equal}")
        return ", ".join(bounds) or "toutes versions"
    return start if has_start else "version non précisée"
