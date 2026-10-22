"""Cache local SQLite : CVE déjà vues et historique des lancements."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .models import Vulnerability

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end   TEXT NOT NULL,
    success      INTEGER NOT NULL,
    new_count    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS seen_cves (
    cve_id     TEXT PRIMARY KEY,
    published  TEXT,
    first_seen TEXT NOT NULL
);
-- CVE déjà signalées comme ajoutées au KEV : une CVE vue à sa publication
-- doit ressortir le jour où elle devient exploitée activement.
CREATE TABLE IF NOT EXISTS seen_kev (
    cve_id     TEXT PRIMARY KEY,
    date_added TEXT,
    first_seen TEXT NOT NULL
);
"""


class Cache:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._db = sqlite3.connect(path)
        self._db.executescript(_SCHEMA)

    def __enter__(self) -> Cache:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    def last_window_end(self) -> datetime | None:
        """Fin de la fenêtre du dernier lancement réussi."""
        row = self._db.execute(
            "SELECT window_end FROM runs WHERE success = 1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return datetime.fromisoformat(row[0]) if row else None

    def record_run(
        self,
        started_at: datetime,
        window_start: datetime,
        window_end: datetime,
        success: bool,
        new_count: int,
    ) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO runs (started_at, window_start, window_end, success, new_count)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    started_at.isoformat(),
                    window_start.isoformat(),
                    window_end.isoformat(),
                    int(success),
                    new_count,
                ),
            )

    def seen_ids(self, cve_ids: Iterable[str]) -> set[str]:
        return self._known_ids("seen_cves", cve_ids)

    def seen_kev_ids(self, cve_ids: Iterable[str]) -> set[str]:
        return self._known_ids("seen_kev", cve_ids)

    def _known_ids(self, table: str, cve_ids: Iterable[str]) -> set[str]:
        ids = list(cve_ids)
        found: set[str] = set()
        # SQLite limite le nombre de paramètres : on procède par lots.
        for i in range(0, len(ids), 500):
            chunk = ids[i : i + 500]
            placeholders = ",".join("?" * len(chunk))
            rows = self._db.execute(
                f"SELECT cve_id FROM {table} WHERE cve_id IN ({placeholders})", chunk
            )
            found.update(r[0] for r in rows)
        return found

    def mark_seen(self, vulns: Iterable[Vulnerability], when: datetime | None = None) -> None:
        when = when or datetime.now(timezone.utc)
        with self._db:
            self._db.executemany(
                "INSERT OR IGNORE INTO seen_cves (cve_id, published, first_seen) VALUES (?, ?, ?)",
                [
                    (v.cve_id, v.published.isoformat() if v.published else None, when.isoformat())
                    for v in vulns
                ],
            )

    def mark_kev_seen(self, vulns: Iterable[Vulnerability], when: datetime | None = None) -> None:
        when = when or datetime.now(timezone.utc)
        with self._db:
            self._db.executemany(
                "INSERT OR IGNORE INTO seen_kev (cve_id, date_added, first_seen) VALUES (?, ?, ?)",
                [(v.cve_id, v.kev.date_added.isoformat(), when.isoformat()) for v in vulns if v.kev],
            )

    def stats(self) -> dict[str, int]:
        return {
            table: self._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("runs", "seen_cves", "seen_kev")
        }

    def recent_runs(self, limit: int = 5) -> list[tuple[str, str, str, bool, int]]:
        """(début du lancement, début de fenêtre, fin de fenêtre, succès, nouvelles CVE)"""
        rows = self._db.execute(
            "SELECT started_at, window_start, window_end, success, new_count"
            " FROM runs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [(a, b, c, bool(d), e) for a, b, c, d, e in rows]
