"""Filtrage et priorisation des vulnérabilités.

Priorisation : failles exploitées (CISA KEV) d'abord, puis score EPSS, puis CVSS.
Les valeurs manquantes sont classées en dernier.

Filtres (section [filters] de la configuration) :
- score CVSS minimum ; les CVE pas encore notées vont dans une section à part ;
- mots-clés produits/éditeurs à surveiller, et mots-clés à exclure ;
- option « exploitées activement seulement » ;
- une faille exploitée n'est jamais écartée par le seuil CVSS (always_keep_exploited).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .config import FilterConfig
from .models import Vulnerability


@dataclass
class FilterOutcome:
    kept: list[Vulnerability] = field(default_factory=list)      # notées, triées par priorité
    unscored: list[Vulnerability] = field(default_factory=list)  # sans CVSS, triées par priorité
    excluded: Counter[str] = field(default_factory=Counter)      # motif → nombre de CVE écartées

    @property
    def all(self) -> list[Vulnerability]:
        return self.kept + self.unscored

    @property
    def excluded_count(self) -> int:
        return sum(self.excluded.values())


def priority_key(v: Vulnerability) -> tuple:
    return (
        not v.is_exploited,
        v.epss_score is None,
        -(v.epss_score or 0.0),
        v.cvss_score is None,
        -(v.cvss_score or 0.0),
        v.cve_id,
    )


def prioritize(vulns: list[Vulnerability]) -> list[Vulnerability]:
    return sorted(vulns, key=priority_key)


# --- Filtres -------------------------------------------------------------------------------


def exclusion_reason(v: Vulnerability, cfg: FilterConfig, check_keywords: bool = True) -> str | None:
    """Motif d'exclusion, ou None si la CVE est conservée."""
    if cfg.only_exploited and not v.is_exploited:
        return "non exploitée activement"
    if v.cvss is None:
        if not cfg.include_unscored:
            return "pas encore notée (CVSS)"
    elif v.cvss.score < cfg.min_cvss and not (v.is_exploited and cfg.always_keep_exploited):
        return f"CVSS < {cfg.min_cvss:g}"
    if check_keywords:
        text = searchable_text(v)
        if cfg.keywords and not any(_contains(text, k) for k in cfg.keywords):
            return "hors mots-clés surveillés"
        for keyword in cfg.exclude_keywords:
            if _contains(text, keyword):
                return f"mot-clé exclu « {keyword} »"
    return None


def prefilter(vulns: list[Vulnerability], cfg: FilterConfig) -> tuple[list[Vulnerability], Counter[str]]:
    """Filtres qui ne dépendent pas de l'enrichissement (CVSS, KEV), appliqués
    avant d'interroger les sources CVE par CVE pour économiser des requêtes.
    Les mots-clés attendent l'enrichissement : CVE.org complète les produits."""
    kept, excluded = [], Counter()
    for v in vulns:
        reason = exclusion_reason(v, cfg, check_keywords=False)
        if reason:
            excluded[reason] += 1
        else:
            kept.append(v)
    return kept, excluded


def apply_filters(
    vulns: list[Vulnerability], cfg: FilterConfig, already_excluded: Counter[str] | None = None
) -> FilterOutcome:
    outcome = FilterOutcome(excluded=Counter(already_excluded or {}))
    for v in vulns:
        reason = exclusion_reason(v, cfg)
        if reason:
            outcome.excluded[reason] += 1
        elif v.cvss is None:
            outcome.unscored.append(v)
        else:
            outcome.kept.append(v)
    outcome.kept = prioritize(outcome.kept)
    outcome.unscored = prioritize(outcome.unscored)
    return outcome


def describe(cfg: FilterConfig) -> list[str]:
    """Filtres actifs, en clair, pour le terminal et le rapport."""
    lines = []
    if cfg.only_exploited:
        lines.append("failles exploitées activement (CISA KEV) uniquement")
    if cfg.min_cvss > 0:
        rule = f"CVSS ≥ {cfg.min_cvss:g}"
        if cfg.always_keep_exploited and not cfg.only_exploited:
            rule += " (sauf failles exploitées, toujours conservées)"
        lines.append(rule)
    if not cfg.include_unscored:
        lines.append("CVE pas encore notées écartées")
    if cfg.keywords:
        lines.append("mots-clés surveillés : " + ", ".join(cfg.keywords))
    if cfg.exclude_keywords:
        lines.append("mots-clés exclus : " + ", ".join(cfg.exclude_keywords))
    return lines


def searchable_text(v: Vulnerability) -> str:
    """Description, éditeurs/produits (NVD, CVE.org, KEV, OSV) et CPE, normalisés."""
    parts = [v.cve_id, v.description]
    parts += [f"{a.vendor} {a.product}" for a in v.affected]
    parts += v.cpes
    if v.kev:
        parts += [v.kev.vendor, v.kev.product, v.kev.name]
    parts += [f.package for f in v.osv_fixes]
    parts += [s for b in v.certfr for s in (b.title, *b.affected_systems)]
    return _normalize(" ".join(parts))


def _normalize(text: str) -> str:
    """Minuscules, ponctuation → espaces (les CPE séparent par « : » et remplacent
    les espaces par « _ »). Les tirets et « + » sont gardés (e-guardian, c++)."""
    return " " + " ".join(re.sub(r"[^\w\-+#]|_", " ", text.lower()).split()) + " "


def _contains(text: str, keyword: str) -> bool:
    """Correspondance par mots entiers : « ssl » ne correspond pas à « openssl »."""
    needle = _normalize(keyword)
    return needle.strip() != "" and needle in text
