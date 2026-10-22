"""Source CERT-FR : avis et alertes en français.

Flux RSS : https://cert.cyber.gouv.fr/avis/feed/ et /alerte/feed/ (40 derniers
bulletins chacun). Chaque bulletin existe en JSON (`<url>/json/`) avec sa liste
de CVE et son contenu Markdown, dont on extrait les sections « Solution » et
« Contournement ». Les JSON sont mis en cache et retéléchargés seulement quand
le bulletin est révisé.
"""

from __future__ import annotations

import html
import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import requests

from ..http import SourceError, build_session, get_json
from ..models import CertFrBulletin
from . import Progress, fetch_each, partial_note

log = logging.getLogger(__name__)

BASE_URL = "https://cert.cyber.gouv.fr"
FEEDS = {"avis": f"{BASE_URL}/avis/feed/", "alerte": f"{BASE_URL}/alerte/feed/"}
_REFERENCE = re.compile(r"CERTFR-\d{4}-(?:AVI|ALE)-\d+")
_SOLUTION_HEADING = re.compile(r"solution|contournement|correctif|recommandation|mesure", re.I)


@dataclass
class CertFrResult:
    bulletins: list[CertFrBulletin] = field(default_factory=list)
    note: str = ""

    def __len__(self) -> int:
        return len(self.bulletins)

    def by_cve(self) -> dict[str, list[CertFrBulletin]]:
        index: dict[str, list[CertFrBulletin]] = {}
        for bulletin in self.bulletins:
            for cve in bulletin.cves:
                index.setdefault(cve, []).append(bulletin)
        return index


@dataclass(frozen=True)
class _FeedItem:
    reference: str
    kind: str
    date: datetime | None


def fetch_bulletins(
    data_dir: Path,
    timeout: int = 30,
    workers: int = 4,
    progress: Progress | None = None,
) -> CertFrResult:
    session = build_session()
    items: list[_FeedItem] = []
    feed_errors: list[str] = []
    for kind, url in FEEDS.items():
        try:
            items.extend(_read_feed(session, url, kind, timeout))
        except SourceError as exc:
            feed_errors.append(f"flux {kind} : {exc}")
    if feed_errors and not items:
        raise SourceError(" ; ".join(feed_errors))

    cache_dir = data_dir / "certfr"
    cache_dir.mkdir(parents=True, exist_ok=True)
    by_ref, errors = fetch_each(
        "CERT-FR", items, lambda item: _load_bulletin(session, item, cache_dir, timeout), workers, progress
    )
    bulletins = sorted(by_ref.values(), key=lambda b: b.date.timestamp() if b.date else 0, reverse=True)
    notes = feed_errors + ([partial_note(errors, len(items))] if errors else [])
    return CertFrResult(bulletins=bulletins, note=" ; ".join(notes))


def _read_feed(session: requests.Session, url: str, kind: str, timeout: int) -> list[_FeedItem]:
    try:
        resp = session.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise SourceError(f"injoignable ({exc.__class__.__name__})") from exc
    if resp.status_code != 200:
        raise SourceError(f"HTTP {resp.status_code}")
    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as exc:
        raise SourceError(f"flux RSS illisible ({exc})") from exc
    items = []
    for node in root.iter("item"):
        match = _REFERENCE.search(node.findtext("link") or node.findtext("guid") or "")
        if not match:
            continue
        items.append(_FeedItem(match.group(0), kind, _parse_rss_date(node.findtext("pubDate"))))
    return items


def _load_bulletin(
    session: requests.Session, item: _FeedItem, cache_dir: Path, timeout: int
) -> CertFrBulletin:
    cache_file = cache_dir / f"{item.reference}.json"
    stamp = item.date.isoformat() if item.date else ""
    cached = _read_cache(cache_file)
    if cached and cached.get("rss_date") == stamp:
        data = cached["data"]
    else:
        data = get_json(session, f"{BASE_URL}/{item.kind}/{item.reference}/json/", "CERT-FR", timeout)
        cache_file.write_text(
            json.dumps({"rss_date": stamp, "data": data}, ensure_ascii=False), encoding="utf-8"
        )
    return parse_bulletin(data, item.kind, item.date)


def _read_cache(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def parse_bulletin(data: dict[str, Any], kind: str, date: datetime | None = None) -> CertFrBulletin:
    reference = data["reference"]
    if date is None:
        revisions = [r.get("revision_date") for r in data.get("revisions", []) if r.get("revision_date")]
        date = _parse_iso(revisions[-1]) if revisions else None
    return CertFrBulletin(
        reference=reference,
        kind=kind,
        title=(data.get("title") or "").strip(),
        url=f"{BASE_URL}/{kind}/{reference}/",
        date=date,
        summary=(data.get("summary") or "").strip(),
        risks=tuple(r["description"] for r in data.get("risks", []) if r.get("description")),
        affected_systems=tuple(
            _affected_label(s) for s in data.get("affected_systems", []) if s.get("description")
        ),
        solution=extract_solution(data.get("content") or ""),
        vendor_advisories=tuple(
            (a.get("title") or a["url"], a["url"]) for a in data.get("vendor_advisories", []) if a.get("url")
        ),
        cves=tuple(c["name"] for c in data.get("cves", []) if c.get("name")),
    )


def extract_solution(markdown: str) -> str:
    """Garde les sections dont le titre évoque une solution ou un contournement."""
    sections: list[str] = []
    current: list[str] | None = None
    for line in markdown.splitlines():
        if re.match(r"#{1,6}\s", line):
            if current:
                sections.append("\n".join(current).strip())
            current = [line] if _SOLUTION_HEADING.search(line) else None
        elif current is not None:
            current.append(line)
    if current:
        sections.append("\n".join(current).strip())
    return clean_markdown("\n\n".join(s for s in sections if s))


def clean_markdown(text: str) -> str:
    """Retire les balises HTML collées par l'éditeur du CERT-FR (<span style=…>)."""
    text = re.sub(r"</?(?:span|div|p|font)\b[^>]*>", "", text, flags=re.I)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = html.unescape(text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _affected_label(system: dict[str, Any]) -> str:
    product = (system.get("product") or {}).get("name", "")
    description = system["description"].strip()
    return description if not product or product in description else f"{product} : {description}"


def _parse_rss_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


def _parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
