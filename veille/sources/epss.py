"""Source EPSS (FIRST) : probabilité d'exploitation d'une CVE dans les 30 jours.

Documentation : https://www.first.org/epss/api
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from ..http import SourceError, build_session, get_json
from ..models import EpssScore
from . import partial_note

log = logging.getLogger(__name__)

API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # limite de l'API par page


@dataclass
class EpssResult:
    scores: dict[str, EpssScore] = field(default_factory=dict)
    note: str = ""

    def __len__(self) -> int:
        return len(self.scores)


def fetch_scores(cve_ids: Iterable[str], timeout: int = 30) -> EpssResult:
    ids = sorted(set(cve_ids))
    result = EpssResult()
    errors: list[str] = []
    session = build_session()
    batches = [ids[i : i + BATCH_SIZE] for i in range(0, len(ids), BATCH_SIZE)]
    for batch in batches:
        try:
            data = get_json(
                session, API_URL, "EPSS", timeout,
                params={"cve": ",".join(batch), "limit": BATCH_SIZE},
            )
        except SourceError as exc:
            errors.append(str(exc))
            if not result.scores and len(errors) >= 2:
                raise  # source en panne : inutile d'insister
            continue
        for item in data.get("data", []):
            try:
                score = parse_item(item)
            except (KeyError, TypeError, ValueError) as exc:
                log.debug("Entrée EPSS ignorée : %s", exc)
                continue
            result.scores[item["cve"]] = score
    if errors and not result.scores:
        raise SourceError(errors[0])
    result.note = partial_note(errors, len(batches)).replace("requêtes", "lots")
    return result


def parse_item(item: dict[str, Any]) -> EpssScore:
    return EpssScore(
        score=float(item["epss"]),
        percentile=float(item["percentile"]),
        date=date.fromisoformat(item["date"]) if item.get("date") else None,
    )
