"""Source NVD : API CVE 2.0 du NIST.

Documentation : https://nvd.nist.gov/developers/vulnerabilities
Limites : 5 requêtes / 30 s sans clé, 50 requêtes / 30 s avec clé (en-tête
`apiKey`). Une requête par dates couvre au plus 120 jours consécutifs.
"""

from __future__ import annotations

import html
import logging
import os
import time
from urllib.parse import urlencode
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from ..http import RateLimiter, SourceError, build_session
from ..models import AffectedProduct, CvssInfo, Reference, Vulnerability, severity_from_score

log = logging.getLogger(__name__)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_ENV = "NVD_API_KEY"
MAX_WINDOW = timedelta(days=120)
PAGE_SIZE = 1000  # max 2000 ; des pages plus légères sont moins souvent coupées
TRANSFER_ATTEMPTS = 3

# Ordre de préférence du score retenu : CVSS 3.1 reste la référence la plus
# répandue pour les seuils ; 4.0 n'est utilisé qu'à défaut de 3.x.
_CVSS_METRICS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)
_IGNORED_CWES = {"NVD-CWE-Other", "NVD-CWE-noinfo"}


class NvdClient:
    def __init__(self, timeout: int = 30, api_key: str | None = None) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get(API_KEY_ENV) or None
        # NVD renvoie parfois 403 au lieu de 429 quand la limite est dépassée.
        self.session = build_session(retry_statuses=(403, 429, 500, 502, 503, 504), backoff=6.0)
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
            self.limiter = RateLimiter(max_calls=45, period=30.0)
        else:
            log.warning("Pas de clé %s : NVD limité à 5 requêtes / 30 s.", API_KEY_ENV)
            self.limiter = RateLimiter(max_calls=5, period=30.0)
        self.timeout = timeout

    @staticmethod
    def has_api_key() -> bool:
        return bool(os.environ.get(API_KEY_ENV))

    def fetch_published(self, start: datetime, end: datetime) -> list[Vulnerability]:
        """CVE publiées entre `start` et `end`, découpées en tranches de 120 jours."""
        vulns: list[Vulnerability] = []
        for chunk_start, chunk_end in split_window(start, end):
            log.info("NVD : CVE publiées du %s au %s", format_date(chunk_start), format_date(chunk_end))
            vulns.extend(
                self._paginate(
                    {
                        "pubStartDate": format_date(chunk_start),
                        "pubEndDate": format_date(chunk_end),
                        "noRejected": None,  # paramètre sans valeur : exclut les CVE rejetées
                    }
                )
            )
        return vulns

    def fetch_kev_added(self, start: datetime, end: datetime) -> list[Vulnerability]:
        """CVE ajoutées au catalogue CISA KEV entre `start` et `end`, quelle que
        soit leur date de publication (une faille ancienne peut devenir exploitée)."""
        vulns: list[Vulnerability] = []
        for chunk_start, chunk_end in split_window(start, end):
            log.info("NVD : CVE ajoutées au KEV du %s au %s", format_date(chunk_start), format_date(chunk_end))
            vulns.extend(
                self._paginate(
                    {
                        "hasKev": None,
                        "kevStartDate": format_date(chunk_start),
                        "kevEndDate": format_date(chunk_end),
                    }
                )
            )
        return vulns

    def fetch_by_id(self, cve_id: str) -> Vulnerability | None:
        result = list(self._paginate({"cveId": cve_id}))
        return result[0] if result else None

    def _paginate(self, params: dict[str, Any]) -> Iterator[Vulnerability]:
        start_index = 0
        while True:
            data = self._get({**params, "startIndex": start_index, "resultsPerPage": PAGE_SIZE})
            items = data.get("vulnerabilities", [])
            for item in items:
                try:
                    yield parse_cve(item["cve"])
                except (KeyError, TypeError, ValueError) as exc:
                    log.warning("Entrée NVD ignorée (format inattendu) : %s", exc)
            start_index += len(items)
            if not items or start_index >= data.get("totalResults", 0):
                return

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        # NVD attend certains paramètres sans valeur (noRejected) : requests
        # ignorerait une valeur None, on construit donc la requête à la main.
        flags = [k for k, v in params.items() if v is None]
        query = "&".join(filter(None, [urlencode({k: v for k, v in params.items() if v is not None}), *flags]))
        # urllib3 relance les échecs de connexion et les codes HTTP, mais pas une
        # coupure en plein transfert (ChunkedEncodingError), fréquente sur NVD.
        for attempt in range(1, TRANSFER_ATTEMPTS + 1):
            self.limiter.wait()
            try:
                resp = self.session.get(f"{API_URL}?{query}", timeout=self.timeout)
                break
            except requests.RequestException as exc:
                if attempt == TRANSFER_ATTEMPTS:
                    raise SourceError(f"NVD injoignable ({exc.__class__.__name__})") from exc
                log.warning("NVD : %s, nouvelle tentative (%d/%d)…",
                            exc.__class__.__name__, attempt + 1, TRANSFER_ATTEMPTS)
                time.sleep(6 * attempt)
        if resp.status_code != 200:
            detail = resp.headers.get("message", "")
            if resp.status_code == 404 and self.api_key:
                detail = detail or "clé API invalide ?"
            raise SourceError(f"NVD a répondu HTTP {resp.status_code} {detail}".strip())
        try:
            return resp.json()
        except ValueError as exc:
            raise SourceError("réponse NVD illisible (JSON invalide)") from exc


def split_window(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    current = start
    while current < end:
        chunk_end = min(current + MAX_WINDOW, end)
        yield current, chunk_end
        current = chunk_end


def format_date(dt: datetime) -> str:
    """Format attendu par NVD (ISO 8601, UTC)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- Analyse d'une entrée CVE -------------------------------------------------


def parse_cve(cve: dict[str, Any]) -> Vulnerability:
    cvss_all = _parse_cvss(cve.get("metrics", {}))
    affected, cpes = _parse_configurations(cve.get("configurations", []))
    return Vulnerability(
        cve_id=cve["id"],
        published=parse_date(cve.get("published")),
        last_modified=parse_date(cve.get("lastModified")),
        status=cve.get("vulnStatus", ""),
        description=_pick_description(cve.get("descriptions", [])),
        cvss=cvss_all[0] if cvss_all else None,
        cvss_all=cvss_all,
        cwe_ids=_parse_cwes(cve.get("weaknesses", [])),
        references=[
            Reference(url=r["url"], source=r.get("source", ""), tags=tuple(r.get("tags", [])))
            for r in cve.get("references", [])
            if r.get("url")
        ],
        affected=affected,
        cpes=cpes,
        affected_source="NVD" if affected else "",
    )


def _pick_description(descriptions: list[dict[str, Any]]) -> str:
    for lang in ("en", "fr"):
        for d in descriptions:
            if d.get("lang") == lang and d.get("value"):
                return _clean_text(d["value"])
    return _clean_text(descriptions[0].get("value", "")) if descriptions else ""


def _clean_text(text: str) -> str:
    """Certains CNA envoient des entités HTML (&nbsp;, &lt;…) dans les descriptions."""
    return " ".join(html.unescape(text).split())


def _parse_cvss(metrics: dict[str, Any]) -> list[CvssInfo]:
    """Tous les scores, triés par préférence (version puis score NVD d'abord)."""
    result: list[CvssInfo] = []
    for key, version in _CVSS_METRICS:
        group: list[CvssInfo] = []
        for metric in metrics.get(key, []):
            data = metric.get("cvssData", {})
            score = data.get("baseScore")
            if score is None:
                continue
            # En v2, la sévérité est au niveau de la métrique et non de cvssData.
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            group.append(
                CvssInfo(
                    version=data.get("version", version),
                    score=float(score),
                    severity=(severity or severity_from_score(float(score))).upper(),
                    vector=data.get("vectorString", ""),
                    source=metric.get("source", ""),
                    primary=metric.get("type") == "Primary",
                )
            )
        group.sort(key=lambda c: not c.primary)
        result.extend(group)
    return result


def _parse_cwes(weaknesses: list[dict[str, Any]]) -> list[str]:
    ordered = sorted(weaknesses, key=lambda w: w.get("type") != "Primary")
    cwes: list[str] = []
    for weakness in ordered:
        for d in weakness.get("description", []):
            value = d.get("value", "")
            if value.startswith("CWE-") and value not in _IGNORED_CWES and value not in cwes:
                cwes.append(value)
    return cwes


def _parse_configurations(
    configurations: list[dict[str, Any]],
) -> tuple[list[AffectedProduct], list[str]]:
    products: dict[tuple[str, str], list[str]] = {}
    cpes: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                parts = _split_cpe(criteria)
                if len(parts) < 6:
                    continue
                if criteria not in cpes:
                    cpes.append(criteria)
                versions = products.setdefault((parts[3], parts[4]), [])
                label = _version_label(parts[5], match)
                if label not in versions:
                    versions.append(label)
    affected = [
        AffectedProduct(vendor=_cpe_display(v), product=_cpe_display(p), versions=tuple(vs))
        for (v, p), vs in products.items()
    ]
    return affected, cpes


def _split_cpe(cpe: str) -> list[str]:
    """Découpe un CPE 2.3 sur ':' en tenant compte des échappements '\\:'."""
    parts, current, escaped = [], [], False
    for char in cpe:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _cpe_display(value: str) -> str:
    return value.replace("_", " ")


def _version_label(version: str, match: dict[str, Any]) -> str:
    bounds = []
    if v := match.get("versionStartIncluding"):
        bounds.append(f"≥ {v}")
    if v := match.get("versionStartExcluding"):
        bounds.append(f"> {v}")
    if v := match.get("versionEndIncluding"):
        bounds.append(f"≤ {v}")
    if v := match.get("versionEndExcluding"):
        bounds.append(f"< {v}")
    if bounds:
        return ", ".join(bounds)
    if version == "*":
        return "toutes versions"
    if version == "-":
        return "version non précisée"
    return version
