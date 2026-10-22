"""Source CISA KEV : catalogue des vulnérabilités exploitées activement.

Catalogue : https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Un seul fichier JSON (environ 2 Mo), mis en cache localement et retéléchargé
seulement s'il a changé (ETag / Last-Modified).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from ..http import SourceError, build_session, fetch_cached
from ..models import KevEntry

log = logging.getLogger(__name__)

CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KevCatalog:
    entries: dict[str, KevEntry] = field(default_factory=dict)
    version: str = ""
    released: datetime | None = None
    note: str = ""  # renseigné si le catalogue vient de la copie locale faute de réseau

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, cve_id: str) -> KevEntry | None:
        return self.entries.get(cve_id)

    def added_since(self, day: date) -> Iterator[KevEntry]:
        return (e for e in self.entries.values() if e.date_added >= day)


def fetch_catalog(data_dir: Path, timeout: int = 30) -> KevCatalog:
    download = fetch_cached(
        build_session(),
        CATALOG_URL,
        data_dir / "kev.json",
        timeout,
        "CISA KEV",
        validate=parse_catalog,
    )
    try:
        catalog = parse_catalog(download.content)
    except ValueError as exc:
        raise SourceError(f"copie locale du catalogue KEV illisible ({exc})") from exc
    if download.stale:
        catalog.note = (
            "catalogue injoignable, copie locale du "
            f"{download.fetched_at.strftime('%Y-%m-%d %H:%M')} UTC utilisée"
        )
    log.info("CISA KEV : %d entrées (version %s)", len(catalog), catalog.version or "?")
    return catalog


def parse_catalog(content: bytes) -> KevCatalog:
    """Lève ValueError si le contenu n'est pas un catalogue KEV exploitable."""
    try:
        data = json.loads(content)
    except ValueError as exc:
        raise ValueError(f"JSON invalide : {exc}") from None
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("champ 'vulnerabilities' absent")

    catalog = KevCatalog(
        version=str(data.get("catalogVersion", "")),
        released=_parse_datetime(data.get("dateReleased")),
    )
    for item in data["vulnerabilities"]:
        try:
            entry = parse_entry(item)
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("Entrée KEV ignorée (format inattendu) : %s", exc)
            continue
        catalog.entries[entry.cve_id] = entry
    if data["vulnerabilities"] and not catalog.entries:
        raise ValueError("aucune entrée lisible")
    return catalog


def parse_entry(item: dict[str, Any]) -> KevEntry:
    return KevEntry(
        cve_id=item["cveID"].strip(),
        vendor=item.get("vendorProject", "").strip(),
        product=item.get("product", "").strip(),
        name=item.get("vulnerabilityName", "").strip(),
        date_added=date.fromisoformat(item["dateAdded"]),
        short_description=item.get("shortDescription", "").strip(),
        required_action=item.get("requiredAction", "").strip(),
        due_date=date.fromisoformat(item["dueDate"]) if item.get("dueDate") else None,
        ransomware=item.get("knownRansomwareCampaignUse", "").strip().lower() == "known",
        notes=item.get("notes", "").strip(),
        cwes=tuple(c for c in item.get("cwes", []) if isinstance(c, str)),
    )


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
