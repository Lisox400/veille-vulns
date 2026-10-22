"""Sources de données. Chaque module expose des fonctions de récupération qui
lèvent `SourceError` en cas de problème ; `run_source` transforme le résultat
en `SourceStatus` pour que l'exécution continue avec les autres sources.

Un résultat peut porter un attribut `note` (réponse partielle, copie locale…)
qui est repris dans le statut affiché."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypeVar

from ..http import SourceError
from ..models import SourceStatus

log = logging.getLogger(__name__)

T = TypeVar("T")
K = TypeVar("K")

Progress = Callable[[str, int, int], None]

# Au-delà de ce nombre d'échecs consécutifs sans aucun succès, la source est
# considérée comme en panne : inutile d'attendre les timeouts des requêtes restantes.
MAX_CONSECUTIVE_FAILURES = 5


def run_source(name: str, func: Callable[[], T]) -> tuple[T | None, SourceStatus]:
    start = time.monotonic()
    try:
        result = func()
    except SourceError as exc:
        log.warning("%s indisponible : %s", name, exc)
        return None, SourceStatus(name, ok=False, message=str(exc), duration=time.monotonic() - start)
    except Exception as exc:  # une source ne doit jamais faire planter l'outil
        log.exception("Erreur inattendue avec la source %s", name)
        return None, SourceStatus(
            name, ok=False, message=f"erreur inattendue : {exc}", duration=time.monotonic() - start
        )
    count = len(result) if hasattr(result, "__len__") else 0
    return result, SourceStatus(
        name, ok=True, message=getattr(result, "note", ""), count=count,
        duration=time.monotonic() - start,
    )


def fetch_each(
    label: str,
    items: Iterable[K],
    func: Callable[[K], T],
    workers: int,
    progress: Progress | None = None,
) -> tuple[dict[K, T], list[str]]:
    """Applique `func` à chaque élément en parallèle.

    Renvoie les résultats non vides et la liste des erreurs. Lève `SourceError`
    si les premières requêtes échouent toutes (source en panne).
    """
    items = list(dict.fromkeys(items))
    results: dict[K, T] = {}
    errors: list[str] = []
    if not items:
        return results, errors
    consecutive = successes = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(func, item): item for item in items}
        for done, future in enumerate(as_completed(futures), 1):
            item = futures[future]
            try:
                value = future.result()
            except SourceError as exc:
                errors.append(f"{item} : {exc}")
                consecutive += 1
                if consecutive >= MAX_CONSECUTIVE_FAILURES and successes == 0:
                    pool.shutdown(wait=False, cancel_futures=True)
                    raise SourceError(f"abandon après {consecutive} échecs ({exc})") from exc
            else:
                consecutive = 0
                successes += 1
                if value:
                    results[item] = value
            if progress:
                progress(label, done, len(items))
    return results, errors


def partial_note(errors: list[str], total: int) -> str:
    if not errors:
        return ""
    log.debug("Échecs : %s", errors)
    return f"{len(errors)}/{total} requêtes en échec (ex. {errors[0]})"
