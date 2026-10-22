"""Point d'entrée : `veille` (menu interactif) ou `veille <commande> [options]`."""

from __future__ import annotations

import argparse
import logging
import re
import shutil
import sys
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from . import __version__, ui
from .cache import Cache
from .checks import run_checks
from .config import Config, ConfigError, FilterConfig, load_config
from .enrichment.cvss import explain
from .http import SourceError
from .report import console
from .services import Toolkit, normalize_ids, parse_since  # noqa: F401  (parse_since : API publique)
from .sources import cwe
from .sources.nvd import NvdClient

log = logging.getLogger("veille")

EXAMPLES = """\
sans commande : menu interactif ([1] nouvelles vulnérabilités, [2] infos, [3] patchs…)

exemples :
  veille                              menu interactif
  veille scan                         nouvelles CVE depuis le dernier lancement + rapport
  veille scan --since 7d -k fortinet  fenêtre de 7 jours, uniquement Fortinet
  veille cve CVE-2024-3400            fiche complète
  veille cve CVE-2024-3400 -s patch   seulement les correctifs
  veille kev --days 30 --ransomware   ajouts KEV liés à des ransomwares
  veille certfr --alertes             dernières alertes CERT-FR
  veille cwe 79                       faiblesse et mesures de prévention
  veille cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  veille sources                      teste la disponibilité des sources
"""


# --- Arguments -----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    # Options globales acceptées avant OU après la sous-commande.
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("-h", "--help", action="help", help="affiche cette aide")
    common.add_argument("-c", "--config", type=Path, help="fichier de configuration (défaut : config.toml)")
    common.add_argument("-v", "--verbose", action="store_true", help="journal détaillé")
    common.add_argument("-q", "--quiet", action="store_true", help="pas de bannière ni de journal")
    common.add_argument("--no-color", action="store_true", help="désactive les couleurs")

    parser = argparse.ArgumentParser(
        prog="veille",
        description=f"Veille sur les vulnérabilités à partir de sources publiques — coded by {ui.AUTHOR}.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
        add_help=False,
    )
    parser.add_argument("--version", action="version", version=f"veille {__version__} · by {ui.AUTHOR}",
                        help="affiche la version")
    sub = parser.add_subparsers(dest="command", metavar="<commande>", title="commandes")
    _french_titles(parser)

    def add(name: str, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text, parents=[common], add_help=False)
        _french_titles(p)
        return p

    add("menu", "menu interactif (comme `veille` sans argument)")

    p = add("scan", "récupère, enrichit et priorise les nouvelles CVE, puis génère le rapport")
    p.add_argument("--since", help="début de la fenêtre : 48h, 7d ou date ISO (défaut : dernier lancement)")
    p.add_argument("-n", "--limit", type=int, default=15, help="lignes affichées (0 = toutes, défaut : 15)")
    p.add_argument("--show-seen", action="store_true", help="inclut les CVE déjà vues")
    p.add_argument("--dry-run", action="store_true", help="ne met pas à jour le cache")
    p.add_argument("--no-enrich", action="store_true", help="NVD + KEV seulement (rapide)")
    f = p.add_argument_group("filtres (surchargent la section [filters] de la configuration)")
    f.add_argument("--min-cvss", type=float, metavar="SCORE", help="score CVSS minimum")
    f.add_argument("--kev-only", action="store_true", help="seulement les failles exploitées activement")
    f.add_argument("-k", "--keyword", action="append", metavar="MOT", help="mot-clé produit/éditeur (répétable)")
    f.add_argument("-x", "--exclude", action="append", metavar="MOT", help="mot-clé à exclure (répétable)")
    f.add_argument("--no-filter", action="store_true", help="ignore tous les filtres de la configuration")
    r = p.add_argument_group("rapport")
    r.add_argument("--no-report", action="store_true", help="pas de rapport, affichage terminal seulement")
    r.add_argument("--format", default="md,html", help="formats du rapport : md, html ou md,html (défaut)")
    r.add_argument("-o", "--output", type=Path, metavar="DOSSIER", help="dossier des rapports (défaut : reports_dir)")

    p = add("cve", "fiche d'une ou plusieurs CVE (toutes sources)")
    p.add_argument("ids", nargs="+", metavar="CVE-ID")
    p.add_argument("-s", "--section", action="append", choices=list(console.SECTIONS),
                   help="n'afficher que certaines sections (répétable) : "
                        "resume, exploit, patch, prevention, certfr")
    p.add_argument("--report", action="store_true", help="exporte aussi les fiches en Markdown et HTML")
    p.add_argument("--format", default="md,html", help="formats exportés : md, html ou md,html (défaut)")
    p.add_argument("-o", "--output", type=Path, metavar="DOSSIER", help="dossier des rapports (défaut : reports_dir)")

    p = add("kev", "derniers ajouts au catalogue CISA KEV")
    p.add_argument("-d", "--days", type=int, default=7, help="période en jours (défaut : 7)")
    p.add_argument("--ransomware", action="store_true", help="seulement les failles utilisées par des ransomwares")
    p.add_argument("-g", "--grep", help="filtre texte (éditeur, produit, nom)")

    p = add("certfr", "derniers avis et alertes du CERT-FR")
    p.add_argument("-d", "--days", type=int, default=7, help="période en jours (défaut : 7)")
    p.add_argument("--alertes", action="store_true", help="seulement les alertes")
    p.add_argument("-g", "--grep", help="filtre texte (titre, systèmes affectés)")

    p = add("epss", "score EPSS (probabilité d'exploitation) d'une ou plusieurs CVE")
    p.add_argument("ids", nargs="+", metavar="CVE-ID")

    p = add("cwe", "fiche d'une faiblesse CWE (catalogue MITRE) ou recherche par nom")
    p.add_argument("ids", nargs="*", metavar="CWE-ID", help="ex. 79, CWE-89")
    p.add_argument("-g", "--grep", help="recherche dans les noms de faiblesses")

    p = add("cvss", "explique un vecteur CVSS (3.x, 4.0 ou 2.0) en français")
    p.add_argument("vector", help='ex. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"')

    add("sources", "teste la disponibilité de chaque source")
    add("status", "état du cache local et derniers lancements")

    p = add("reset", "vide le cache local (CVE vues, catalogues téléchargés)")
    p.add_argument("-y", "--yes", action="store_true", help="ne pas demander de confirmation")
    return parser


def _french_titles(parser: argparse.ArgumentParser) -> None:
    parser._optionals.title = "options"
    parser._positionals.title = "arguments"


def parse_formats(value: str) -> tuple[str, ...]:
    formats = tuple(dict.fromkeys(f.strip().lower() for f in value.split(",") if f.strip()))
    if not formats or any(f not in ("md", "html") for f in formats):
        raise ValueError(f"--format invalide : {value!r} (attendu : md, html ou md,html)")
    return formats


def effective_filters(args: argparse.Namespace, config: Config) -> FilterConfig:
    """Filtres de la configuration, surchargés par les options de la ligne de commande."""
    if args.no_filter:
        return FilterConfig(always_keep_exploited=config.filters.always_keep_exploited)
    filters = config.filters
    changes: dict = {}
    if args.min_cvss is not None:
        if not 0 <= args.min_cvss <= 10:
            raise ValueError("--min-cvss doit être compris entre 0 et 10")
        changes["min_cvss"] = args.min_cvss
    if args.kev_only:
        changes["only_exploited"] = True
    if args.keyword:
        changes["keywords"] = tuple(args.keyword)
    if args.exclude:
        changes["exclude_keywords"] = filters.exclude_keywords + tuple(args.exclude)
    return replace(filters, **changes)


def _print_reports(paths: list[Path]) -> None:
    ui.section("RAPPORT")
    for path in paths:
        ui.ok(str(path))


# --- Commandes -------------------------------------------------------------------------


def cmd_menu(args: argparse.Namespace, config: Config) -> int:
    from .interactive import Menu

    return Menu(config).run()


def cmd_scan(args: argparse.Namespace, config: Config) -> int:
    formats = parse_formats(args.format)
    filters = effective_filters(args, config)
    tk = Toolkit(config, progress=ui.progress)
    start, end = tk.scan_window(args.since)
    ui.info(f"Fenêtre {ui.c(f'{start:%Y-%m-%d %H:%M}', 'bold')} → {ui.c(f'{end:%Y-%m-%d %H:%M}', 'bold')} UTC")
    run = tk.scan(start, end, filters, show_seen=args.show_seen, dry_run=args.dry_run, enrich=not args.no_enrich)

    ui.section("SOURCES")
    console.print_statuses(run.statuses)
    console.print_scan(run.outcome, len(run.result.fetched), run.new_count, args.limit, run.filters)
    if not args.no_report:
        try:
            _print_reports(tk.scan_report(run, formats, args.output.resolve() if args.output else None))
        except OSError as exc:
            ui.error(f"Écriture du rapport impossible : {exc}")
    print(ui.c("\n  détail d'une faille : veille cve <CVE-ID> [-s patch]  ·  menu : veille", "gray"))
    print()
    return 0 if run.result.nvd_ok else 1


def cmd_cve(args: argparse.Namespace, config: Config) -> int:
    ids = normalize_ids(args.ids)
    formats = parse_formats(args.format)
    tk = Toolkit(config, progress=ui.progress)
    vulns, statuses = tk.lookup(ids)
    for status in statuses:
        if not status.ok:
            ui.warn(f"{status.name} : {status.message}")
    for v in vulns:
        if not v.description and not v.kev:
            ui.warn(f"{v.cve_id} introuvable (NVD, CISA KEV)")
            continue
        console.print_detail(v, args.section)
    if args.report:
        _print_reports(tk.lookup_report(vulns, statuses, formats, args.output.resolve() if args.output else None))
    print()
    return 0


def cmd_kev(args: argparse.Namespace, config: Config) -> int:
    tk = Toolkit(config)
    entries, scores = tk.kev_recent(args.days, args.ransomware, args.grep)
    if tk.kev_note:
        ui.warn(tk.kev_note)
    console.print_kev(entries, scores)
    print()
    return 0


def cmd_certfr(args: argparse.Namespace, config: Config) -> int:
    console.print_certfr(Toolkit(config, progress=ui.progress).certfr_recent(args.days, args.alertes, args.grep))
    print()
    return 0


def cmd_epss(args: argparse.Namespace, config: Config) -> int:
    ids = normalize_ids(args.ids)
    console.print_epss(ids, Toolkit(config).epss(ids))
    print()
    return 0


def cmd_cwe(args: argparse.Namespace, config: Config) -> int:
    if not args.ids and not args.grep:
        raise ValueError("indique au moins un identifiant CWE ou une recherche (-g)")
    ids = []
    for value in args.ids:
        if not re.fullmatch(r"(?i)(cwe-)?\d+", value.strip()):
            raise ValueError(f"identifiant invalide : {value!r} (attendu : 79 ou CWE-79)")
        ids.append(cwe.normalize_id(value))
    catalog = Toolkit(config).cwe_catalog()
    if catalog.note:
        ui.warn(catalog.note)
    if args.grep:
        needle = args.grep.lower()
        matches = sorted((i for i in catalog.entries.values() if needle in i.name.lower()),
                         key=lambda i: int(i.cwe_id.split("-")[1]))
        ui.section(f"CWE · {len(matches)} RÉSULTATS POUR « {args.grep} »")
        for info in matches:
            kind = ui.c(" (catégorie)", "gray") if info.kind == "category" else ""
            print(f"  {ui.c(info.cwe_id.ljust(9), 'bold', 'byellow')} {info.name}{kind}")
    for cwe_id in ids:
        info = catalog.get(cwe_id)
        if info is None:
            ui.warn(f"{cwe_id} absente du catalogue CWE {catalog.version}")
            continue
        console.print_cwe(info)
    print()
    return 0


def cmd_cvss(args: argparse.Namespace, config: Config) -> int:
    explanation = explain(args.vector)
    if explanation is None:
        raise ValueError(f"vecteur CVSS illisible : {args.vector!r}")
    ui.section(f"CVSS {explanation.version}")
    print(ui.c(f"  {args.vector}", "gray"))
    print()
    console.print_cvss_explanation(explanation, indent=2)
    print()
    return 0


def cmd_sources(args: argparse.Namespace, config: Config) -> int:
    ui.section("DIAGNOSTIC DES SOURCES")
    results = run_checks(timeout=min(config.general.timeout, 15))
    for r in results:
        line = f"{r.name:<10} {ui.c(f'{r.latency * 1000:>6.0f} ms', 'gray')}  {r.detail:<10} {ui.c(r.url, 'gray')}"
        (ui.ok if r.ok else ui.error)(line)
    key = "présente" if NvdClient.has_api_key() else ui.c("absente (5 req / 30 s)", "byellow")
    ui.info(f"Clé API NVD : {key}")
    return 0 if all(r.ok for r in results) else 1


def print_status(config: Config) -> None:
    data_dir = config.general.data_dir
    ui.section("ÉTAT DU CACHE")
    print(f"  Configuration : {config.path or ui.c('aucune (valeurs par défaut)', 'gray')}")
    print(f"  Données       : {data_dir}")
    db_path = data_dir / "veille.db"
    if not db_path.exists():
        print(ui.c("\n  Aucun lancement pour l'instant : lance un scan.", "gray"))
        return
    with Cache(db_path) as cache:
        stats, runs = cache.stats(), cache.recent_runs(5)
    print(f"  CVE vues      : {ui.c(stats['seen_cves'], 'bold')}  ·  ajouts KEV signalés : "
          f"{ui.c(stats['seen_kev'], 'bold')}  ·  lancements : {stats['runs']}")
    for name in ("kev.json", "certfr", "cwec_latest.xml.zip"):
        path = data_dir / name
        if path.exists():
            when = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"  {name:<13} : mis à jour le {when}")
    ui.section("DERNIERS LANCEMENTS")
    for started, w_start, w_end, success, count in runs:
        state = ui.c("OK ", "bgreen") if success else ui.c("ÉCHEC", "bred")
        print(f"  {started[:16].replace('T', ' ')}  {state}  fenêtre {w_start[:16].replace('T', ' ')} → "
              f"{w_end[:16].replace('T', ' ')}  {ui.c(count, 'bold')} retenues")


def cmd_status(args: argparse.Namespace, config: Config) -> int:
    print_status(config)
    print()
    return 0


CACHE_FILES = (
    "veille.db", "kev.json", "kev.json.meta.json", "certfr",
    "cwec_latest.xml.zip", "cwec_latest.xml.zip.meta.json",
)


def cmd_reset(args: argparse.Namespace, config: Config) -> int:
    data_dir = config.general.data_dir
    # Seuls les fichiers créés par l'outil sont supprimés, jamais le dossier entier.
    targets = [p for p in (data_dir / n for n in CACHE_FILES) if p.exists()]
    if not targets:
        ui.info("Cache déjà vide.")
        return 0
    for path in targets:
        print(f"  - {path}")
    if not args.yes:
        answer = input(ui.c("[?] ", "bmagenta", "bold") + "Supprimer ces éléments ? [o/N] ").strip().lower()
        if answer not in ("o", "oui", "y", "yes"):
            ui.info("Annulé.")
            return 0
    for path in targets:
        shutil.rmtree(path) if path.is_dir() else path.unlink()
    ui.ok("Cache vidé : le prochain scan repartira sur les dernières 24 h.")
    return 0


COMMANDS = {
    "menu": cmd_menu,
    "scan": cmd_scan,
    "cve": cmd_cve,
    "kev": cmd_kev,
    "certfr": cmd_certfr,
    "epss": cmd_epss,
    "cwe": cmd_cwe,
    "cvss": cmd_cvss,
    "sources": cmd_sources,
    "status": cmd_status,
    "reset": cmd_reset,
}


# --- Point d'entrée ------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ui.init(color=False)  # UTF-8 dès maintenant : argparse peut écrire (aide, erreurs)
    parser = build_parser()
    args = parser.parse_args(argv)
    for name, default in (("config", Path("config.toml")), ("verbose", False), ("quiet", False), ("no_color", False)):
        if not hasattr(args, name):
            setattr(args, name, default)

    ui.init(color=False if args.no_color else None)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ui.LogFormatter("%(message)s"))
    level = logging.DEBUG if args.verbose else logging.ERROR if args.quiet else logging.WARNING
    logging.basicConfig(level=level, handlers=[handler], force=True)
    logging.getLogger("urllib3").setLevel(logging.INFO if args.verbose else logging.WARNING)

    command = args.command
    if command is None:
        # Sans commande : menu dans un terminal, aide sinon (redirection, script).
        if not sys.stdin.isatty():
            ui.banner()
            parser.print_help()
            return 0
        command = "menu"
    if not args.quiet and command != "menu":
        ui.banner()

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        ui.error(f"Configuration invalide : {exc}")
        return 2
    try:
        return COMMANDS[command](args, config)
    except SourceError as exc:
        ui.error(str(exc))
        return 1
    except ValueError as exc:
        ui.error(str(exc))
        return 2
    except KeyboardInterrupt:
        print(file=sys.stderr)
        ui.warn("Interrompu.")
        return 130
