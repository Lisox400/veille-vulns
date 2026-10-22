"""Accès réseau partagé : session HTTP avec retry, timeouts et limiteur de débit."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"veille-vulns/{__version__} (outil de veille personnel)"
DEFAULT_RETRY_STATUSES = (429, 500, 502, 503, 504)


class SourceError(Exception):
    """Erreur récupérable d'une source : l'exécution continue avec les autres."""


def build_session(
    retry_statuses: tuple[int, ...] = DEFAULT_RETRY_STATUSES,
    retries: int = 3,
    backoff: float = 2.0,
) -> requests.Session:
    """Session avec retry et backoff exponentiel (backoff, 2×backoff, 4×backoff…).

    `Retry-After` est respecté quand le serveur l'envoie.
    """
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=backoff,
        status_forcelist=retry_statuses,
        allowed_methods=frozenset({"GET", "POST"}),
        respect_retry_after_header=True,
        raise_on_status=False,  # on récupère la dernière réponse pour un message clair
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers["User-Agent"] = USER_AGENT
    return session


class RateLimiter:
    """Fenêtre glissante : au plus `max_calls` appels par `period` secondes."""

    def __init__(self, max_calls: int, period: float) -> None:
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            while self._calls and now - self._calls[0] >= self.period:
                self._calls.popleft()
            if len(self._calls) >= self.max_calls:
                time.sleep(self.period - (now - self._calls[0]))
                self._calls.popleft()
            self._calls.append(time.monotonic())


def get_json(
    session: requests.Session,
    url: str,
    label: str,
    timeout: int,
    params: dict | None = None,
    not_found_ok: bool = False,
):
    """GET JSON avec erreurs converties en `SourceError`. 404 → None si `not_found_ok`."""
    try:
        resp = session.get(url, params=params, timeout=timeout)
    except requests.RequestException as exc:
        raise SourceError(f"{label} injoignable ({exc.__class__.__name__})") from exc
    if resp.status_code == 404 and not_found_ok:
        return None
    if resp.status_code != 200:
        raise SourceError(f"{label} a répondu HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as exc:
        raise SourceError(f"réponse {label} illisible (JSON invalide)") from exc


@dataclass(frozen=True)
class CachedDownload:
    content: bytes
    fetched_at: datetime     # dernière confirmation de fraîcheur auprès du serveur
    stale: bool = False      # True si le serveur était injoignable et qu'on sert la copie locale


def fetch_cached(
    session: requests.Session,
    url: str,
    path: Path,
    timeout: int,
    label: str,
    validate: Callable[[bytes], object] | None = None,
    max_age: timedelta | None = None,
) -> CachedDownload:
    """Télécharge `url` vers `path` avec requête conditionnelle (ETag / Last-Modified).

    `validate` est appelé sur un nouveau contenu avant de remplacer la copie
    locale ; il lève `ValueError` si le contenu est inutilisable. Si le serveur
    est injoignable ou le contenu invalide et qu'une copie locale existe, elle
    est renvoyée avec `stale=True` ; sinon `SourceError` est levée.
    Avec `max_age`, une copie locale plus récente est utilisée sans contacter le serveur.
    """
    meta_path = path.with_name(path.name + ".meta.json")
    meta = _read_meta(meta_path) if path.exists() else {}
    if max_age and meta.get("fetched_at"):
        fetched_at = datetime.fromisoformat(meta["fetched_at"])
        if datetime.now(timezone.utc) - fetched_at < max_age:
            log.debug("%s : copie locale du %s utilisée (moins de %s)", label, fetched_at, max_age)
            return CachedDownload(path.read_bytes(), fetched_at)
    headers = {}
    if etag := meta.get("etag"):
        headers["If-None-Match"] = etag
    if last_modified := meta.get("last_modified"):
        headers["If-Modified-Since"] = last_modified

    now = datetime.now(timezone.utc)
    try:
        resp = session.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 304:
            log.debug("%s : copie locale à jour (304)", label)
            _write_meta(meta_path, {**meta, "fetched_at": now.isoformat()})
            return CachedDownload(path.read_bytes(), now)
        if resp.status_code != 200:
            raise SourceError(f"{label} a répondu HTTP {resp.status_code}")
        if validate:
            try:
                validate(resp.content)
            except ValueError as exc:
                raise SourceError(f"{label} : contenu invalide ({exc})") from exc
    except (requests.RequestException, SourceError) as exc:
        message = str(exc) if isinstance(exc, SourceError) else f"{label} injoignable ({exc.__class__.__name__})"
        if not path.exists():
            raise SourceError(message) from exc
        fetched_at = datetime.fromisoformat(meta["fetched_at"]) if meta.get("fetched_at") else None
        log.warning("%s, utilisation de la copie locale", message)
        return CachedDownload(path.read_bytes(), fetched_at or now, stale=True)

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(resp.content)
    tmp.replace(path)
    _write_meta(meta_path, {
        "url": url,
        "etag": resp.headers.get("ETag"),
        "last_modified": resp.headers.get("Last-Modified"),
        "fetched_at": now.isoformat(),
    })
    return CachedDownload(resp.content, now)


def _read_meta(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_meta(path: Path, meta: dict) -> None:
    path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
