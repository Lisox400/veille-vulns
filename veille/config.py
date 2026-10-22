"""Lecture et validation du fichier de configuration TOML."""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class GeneralConfig:
    data_dir: Path = Path("data")
    reports_dir: Path = Path("reports")
    first_run_hours: int = 24
    overlap_hours: int = 2
    timeout: int = 30


@dataclass(frozen=True)
class FilterConfig:
    min_cvss: float = 0.0
    include_unscored: bool = True
    only_exploited: bool = False
    always_keep_exploited: bool = True
    keywords: tuple[str, ...] = ()
    exclude_keywords: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourcesConfig:
    epss: bool = True
    certfr: bool = True
    osv: bool = True
    cveorg: bool = True
    cwe: bool = True
    workers: int = 8     # requêtes parallèles pour les sources interrogées CVE par CVE


@dataclass(frozen=True)
class Config:
    general: GeneralConfig
    filters: FilterConfig
    sources: SourcesConfig = SourcesConfig()
    path: Path | None = None  # fichier lu, None si valeurs par défaut


def load_config(path: Path) -> Config:
    """Charge `path`. Si le fichier n'existe pas, utilise les valeurs par défaut."""
    if not path.exists():
        log.info("Fichier de configuration %s introuvable : valeurs par défaut utilisées.", path)
        raw: dict[str, Any] = {}
        base_dir = Path.cwd()
        source: Path | None = None
    else:
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"{path} : fichier TOML invalide ({exc})") from exc
        base_dir = path.resolve().parent
        source = path

    for section in raw:
        if section not in ("general", "filters", "sources"):
            log.warning("Section [%s] inconnue dans la configuration, ignorée.", section)

    general = _build(GeneralConfig, raw.get("general", {}), "general")
    filters = _build(FilterConfig, raw.get("filters", {}), "filters")
    sources = _build(SourcesConfig, raw.get("sources", {}), "sources")

    general = GeneralConfig(
        data_dir=_resolve(base_dir, general.data_dir),
        reports_dir=_resolve(base_dir, general.reports_dir),
        first_run_hours=general.first_run_hours,
        overlap_hours=general.overlap_hours,
        timeout=general.timeout,
    )
    _validate(general, filters)
    if not 1 <= sources.workers <= 32:
        raise ConfigError("sources.workers doit être compris entre 1 et 32")
    return Config(general=general, filters=filters, sources=sources, path=source)


def _build(cls, values: Any, section: str):
    if not isinstance(values, dict):
        raise ConfigError(f"[{section}] doit être une table TOML")
    known = {f.name: f for f in fields(cls)}
    kwargs = {}
    for key, value in values.items():
        if key not in known:
            log.warning("Option %s.%s inconnue, ignorée.", section, key)
            continue
        kwargs[key] = _coerce(known[key].default, value, f"{section}.{key}")
    return cls(**kwargs)


def _coerce(default: Any, value: Any, name: str) -> Any:
    """Convertit `value` au type de la valeur par défaut, avec un message clair."""
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{name} doit valoir true ou false")
        return value
    if isinstance(default, (int, float)):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{name} doit être un nombre")
        return type(default)(value)
    if isinstance(default, Path):
        if not isinstance(value, str):
            raise ConfigError(f"{name} doit être un chemin (chaîne)")
        return Path(value)
    if isinstance(default, tuple):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{name} doit être une liste de chaînes")
        return tuple(v.strip() for v in value if v.strip())
    return value


def _resolve(base_dir: Path, path: Path) -> Path:
    return path if path.is_absolute() else base_dir / path


def _validate(general: GeneralConfig, filters: FilterConfig) -> None:
    if not 0.0 <= filters.min_cvss <= 10.0:
        raise ConfigError("filters.min_cvss doit être compris entre 0 et 10")
    if general.first_run_hours <= 0:
        raise ConfigError("general.first_run_hours doit être positif")
    if general.overlap_hours < 0:
        raise ConfigError("general.overlap_hours ne peut pas être négatif")
    if general.timeout <= 0:
        raise ConfigError("general.timeout doit être positif")
