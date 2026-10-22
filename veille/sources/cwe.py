"""Source CWE (MITRE) : catalogue des types de faiblesses et mesures de prévention.

Catalogue : https://cwe.mitre.org/data/downloads.html (XML zippé, ~2 Mo).
Mis en cache localement ; le serveur n'est recontacté qu'une fois par semaine
(et seulement pour vérifier s'il a changé). Le contenu est en anglais.
"""

from __future__ import annotations

import io
import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from ..http import SourceError, build_session, fetch_cached
from ..models import CweConsequence, CweInfo, CweMitigation

log = logging.getLogger(__name__)

CATALOG_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
MAX_AGE = timedelta(days=7)


@dataclass
class CweCatalog:
    entries: dict[str, CweInfo] = field(default_factory=dict)
    version: str = ""
    note: str = ""

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, cwe_id: str) -> CweInfo | None:
        return self.entries.get(normalize_id(cwe_id))


def normalize_id(value: str) -> str:
    """'79', 'cwe-79', 'CWE-79' → 'CWE-79'."""
    digits = re.sub(r"(?i)^cwe-", "", value.strip())
    return f"CWE-{digits}"


def fetch_catalog(data_dir: Path, timeout: int = 60) -> CweCatalog:
    download = fetch_cached(
        build_session(),
        CATALOG_URL,
        data_dir / "cwec_latest.xml.zip",
        timeout,
        "CWE MITRE",
        validate=parse_archive,
        max_age=MAX_AGE,
    )
    try:
        catalog = parse_archive(download.content)
    except ValueError as exc:
        raise SourceError(f"copie locale du catalogue CWE illisible ({exc})") from exc
    if download.stale:
        catalog.note = f"catalogue injoignable, copie locale du {download.fetched_at:%Y-%m-%d} utilisée"
    return catalog


def parse_archive(content: bytes) -> CweCatalog:
    """Lève ValueError si l'archive ne contient pas de catalogue exploitable."""
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = [n for n in archive.namelist() if n.endswith(".xml")]
            if not names:
                raise ValueError("aucun fichier XML dans l'archive")
            xml = archive.read(names[0])
    except zipfile.BadZipFile as exc:
        raise ValueError(f"archive ZIP invalide ({exc})") from None
    return parse_xml(xml)


def parse_xml(xml: bytes) -> CweCatalog:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError(f"XML invalide ({exc})") from None
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    catalog = CweCatalog(version=root.get("Version", ""))

    for node in root.iter(f"{ns}Weakness"):
        info = _parse_weakness(node, ns)
        catalog.entries[info.cwe_id] = info
    for node in root.iter(f"{ns}Category"):
        cwe_id = f"CWE-{node.get('ID')}"
        catalog.entries.setdefault(cwe_id, CweInfo(
            cwe_id=cwe_id,
            name=node.get("Name", ""),
            kind="category",
            description=_text(node.find(f"{ns}Summary")),
            status=node.get("Status", ""),
        ))
    if not catalog.entries:
        raise ValueError("aucune faiblesse trouvée")
    log.debug("CWE : %d entrées (version %s)", len(catalog), catalog.version)
    return catalog


def _parse_weakness(node: ET.Element, ns: str) -> CweInfo:
    consequences = tuple(
        CweConsequence(
            scopes=tuple(s.text.strip() for s in c.findall(f"{ns}Scope") if s.text),
            impacts=tuple(i.text.strip() for i in c.findall(f"{ns}Impact") if i.text),
        )
        for c in node.findall(f"{ns}Common_Consequences/{ns}Consequence")
    )
    mitigations = tuple(
        CweMitigation(
            phases=tuple(p.text.strip() for p in m.findall(f"{ns}Phase") if p.text),
            strategy=(m.findtext(f"{ns}Strategy") or "").strip(),
            description=_text(m.find(f"{ns}Description")),
            effectiveness=(m.findtext(f"{ns}Effectiveness") or "").strip(),
        )
        for m in node.findall(f"{ns}Potential_Mitigations/{ns}Mitigation")
    )
    return CweInfo(
        cwe_id=f"CWE-{node.get('ID')}",
        name=node.get("Name", ""),
        description=_text(node.find(f"{ns}Description")),
        likelihood=(node.findtext(f"{ns}Likelihood_Of_Exploit") or "").strip(),
        consequences=consequences,
        mitigations=tuple(m for m in mitigations if m.description),
        status=node.get("Status", ""),
    )


def _text(node: ET.Element | None) -> str:
    """Texte d'un élément pouvant contenir du XHTML (<html:p>, <html:li>…), un paragraphe par bloc."""
    if node is None:
        return ""
    blocks = ["".join(child.itertext()) for child in node]
    paragraphs = [_clean(p) for p in [node.text or "", *blocks]]
    return "\n\n".join(p for p in paragraphs if p)


def _clean(text: str) -> str:
    """Espaces normalisés, renvois bibliographiques ([REF-1482]) retirés."""
    text = re.sub(r"\s*\[REF-\d+\]?", "", text)
    return " ".join(text.split())
