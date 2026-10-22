"""Mode interactif : menu numéroté façon outil de pentest.

Lancé par `veille` sans argument (ou `veille menu`). Chaque écran affiche peu
d'informations à la fois ; on descend dans le détail en choisissant un numéro.
"""

from __future__ import annotations

import os
import re
import webbrowser
from pathlib import Path

from . import ui
from .checks import run_checks
from .config import Config
from .enrichment.cvss import explain
from .http import SourceError
from .models import CertFrBulletin, Vulnerability
from .report import console
from .services import Toolkit, normalize_ids
from .sources import cwe as cwe_source
from .sources.nvd import NvdClient

PAGE_SIZE = 10

MAIN_MENU = [
    ("1", "Nouvelles vulnérabilités", "scan depuis le dernier lancement"),
    ("2", "Infos sur une vulnérabilité", "fiche d'une CVE"),
    ("3", "Patchs / correctifs", "comment corriger une CVE"),
    ("4", "Failles exploitées (KEV)", "derniers ajouts CISA"),
    ("5", "Alertes CERT-FR", "avis et alertes en français"),
    ("6", "Faiblesse CWE", "type de faille et prévention"),
    ("7", "Décoder un vecteur CVSS", "en clair, en français"),
    ("8", "Ouvrir le dernier rapport", "page HTML dans le navigateur"),
    ("9", "État & diagnostic", "cache, sources, clé NVD"),
    ("0", "Quitter", ""),
]

VULN_MENU = [
    ("1", "resume"),
    ("2", "exploit"),
    ("3", "patch"),
    ("4", "prevention"),
    ("5", "certfr"),
]


class Menu:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.tk = Toolkit(config, progress=ui.progress)

    # --- Boucle principale ------------------------------------------------------------

    def run(self) -> int:
        actions = {
            "1": self.new_vulns, "2": self.vuln_info, "3": self.vuln_patch, "4": self.kev,
            "5": self.certfr, "6": self.cwe, "7": self.cvss, "8": self.open_report, "9": self.status,
        }
        while True:
            self.home()
            try:
                choice = ui.ask()
            except ui.Back:
                choice = "0"
            if choice in ("0", "q", "quit", "exit"):
                print(ui.c("\n  bye · coded by lisox\n", "gray"))
                return 0
            action = actions.get(choice)
            if not action:
                continue
            try:
                action()
            except ui.Back:
                continue
            except SourceError as exc:
                ui.error(str(exc))
                ui.pause()
            except ValueError as exc:
                ui.error(str(exc))
                ui.pause()

    def home(self) -> None:
        ui.clear()
        ui.banner()
        key = ui.c("clé NVD ✔", "bgreen") if NvdClient.has_api_key() else ui.c("clé NVD absente", "byellow")
        last = self.tk.last_scan
        scan = f"dernier scan : {len(last.outcome.all)} failles" if last else "aucun scan dans cette session"
        print(f"  {key}  {ui.c('·', 'gray')}  {ui.c(scan, 'gray')}\n")
        for key_, label, hint in MAIN_MENU:
            ui.menu_item(key_, label, hint)

    # --- [1] Nouvelles vulnérabilités ------------------------------------------------------

    def new_vulns(self) -> None:
        if self.tk.last_scan:
            ui.section("NOUVELLES VULNÉRABILITÉS")
            ui.menu_item("1", "Revoir le dernier scan")
            ui.menu_item("2", "Nouveau scan")
            ui.menu_item("0", "Retour")
            choice = ui.ask()
            if choice == "1":
                return self.browse(self.tk.last_scan.outcome.all, "DERNIER SCAN")
            if choice != "2":
                return
        ui.section("NOUVEAU SCAN")
        print(ui.c("  Entrée = depuis le dernier lancement · ou 24h, 48h, 7d, 2026-10-01", "gray"))
        since = ui.ask("fenêtre")
        start, end = self.tk.scan_window(since or None)
        ui.info(f"Fenêtre {start:%Y-%m-%d %H:%M} → {end:%Y-%m-%d %H:%M} UTC, scan en cours…")
        run = self.tk.scan(start, end)
        try:
            paths = self.tk.scan_report(run)
        except OSError as exc:
            ui.error(f"Rapport non écrit : {exc}")
            paths = []

        ui.clear()
        ui.section("SOURCES")
        console.print_statuses(run.statuses)
        _print_scan_summary(run, paths)
        ui.pause()
        self.browse(run.outcome.all, "NOUVELLES VULNÉRABILITÉS")

    # --- Liste paginée ------------------------------------------------------------------------

    def browse(self, vulns: list[Vulnerability], title: str) -> None:
        if not vulns:
            ui.info("Rien de nouveau qui corresponde aux critères.")
            ui.pause()
            return
        page = 0
        pages = (len(vulns) - 1) // PAGE_SIZE + 1
        while True:
            ui.clear()
            ui.section(f"{title} · {len(vulns)} · page {page + 1}/{pages}")
            first = page * PAGE_SIZE
            for index, v in enumerate(vulns[first:first + PAGE_SIZE], first + 1):
                _print_row(index, v)
            nav = ["[n°] ouvrir la fiche"]
            if page + 1 < pages:
                nav.append("[s] suivant")
            if page > 0:
                nav.append("[p] précédent")
            nav += ["[r] rapport", "[0] retour"]
            print(ui.c("\n  " + " · ".join(nav), "gray"))
            choice = ui.ask().lower()
            if choice in ("0", ""):
                return
            if choice == "s" and page + 1 < pages:
                page += 1
            elif choice == "p" and page > 0:
                page -= 1
            elif choice == "r":
                self.open_report()
            elif choice.isdigit() and 1 <= int(choice) <= len(vulns):
                self.vuln_view(vulns[int(choice) - 1])

    # --- Fiche d'une vulnérabilité ---------------------------------------------------------------

    def vuln_view(self, v: Vulnerability, start_section: str | None = None) -> None:
        section = start_section
        while True:
            ui.clear()
            console.print_card(v)
            if section:
                console.SECTION_PRINTERS[section](v)
            print()
            for key, name in VULN_MENU:
                marker = ui.c(" ◂", "bgreen") if name == section else ""
                ui.menu_item(key, console.SECTIONS[name] + marker)
            ui.menu_item("6", "Tout afficher")
            ui.menu_item("7", "Exporter la fiche (rapport MD + HTML)")
            ui.menu_item("0", "Retour")
            choice = ui.ask(v.cve_id.lower())
            if choice in ("0", ""):
                return
            if choice == "6":
                ui.clear()
                console.print_detail(v)
                ui.pause()
                section = None
            elif choice == "7":
                paths = self.tk.lookup_report([v], [])
                for path in paths:
                    ui.ok(str(path))
                ui.pause()
            else:
                section = dict(VULN_MENU).get(choice, section)

    def _ask_cve(self) -> Vulnerability:
        print(ui.c("  ex. CVE-2024-3400", "gray"))
        value = ui.ask("cve")
        if not value:
            raise ui.Back
        ids = normalize_ids([value if value.upper().startswith("CVE-") else f"CVE-{value}"])
        ui.info(f"Recherche de {ids[0]} dans toutes les sources…")
        vulns, statuses = self.tk.lookup(ids)
        for status in statuses:
            if not status.ok:
                ui.warn(f"{status.name} : {status.message}")
        v = vulns[0]
        if not v.description and not v.kev:
            raise ValueError(f"{v.cve_id} introuvable (NVD, CISA KEV)")
        return v

    def vuln_info(self) -> None:
        ui.section("INFOS SUR UNE VULNÉRABILITÉ")
        self.vuln_view(self._ask_cve(), "resume")

    def vuln_patch(self) -> None:
        ui.section("PATCHS / CORRECTIFS")
        self.vuln_view(self._ask_cve(), "patch")

    # --- [4] KEV ---------------------------------------------------------------------------------------

    def kev(self) -> None:
        ui.section("FAILLES EXPLOITÉES · CISA KEV")
        days = _ask_int("nombre de jours", 7)
        entries, scores = self.tk.kev_recent(days)
        if self.tk.kev_note:
            ui.warn(self.tk.kev_note)
        while True:
            ui.clear()
            console.print_kev(entries, scores, numbered=True)
            if not entries:
                ui.pause()
                return
            print(ui.c("\n  [n°] fiche complète · [0] retour", "gray"))
            choice = ui.ask("kev")
            if choice in ("0", ""):
                return
            if choice.isdigit() and 1 <= int(choice) <= len(entries):
                ui.info("Chargement de la fiche…")
                vulns, _ = self.tk.lookup([entries[int(choice) - 1].cve_id])
                self.vuln_view(vulns[0], "exploit")

    # --- [5] CERT-FR -------------------------------------------------------------------------------------

    def certfr(self) -> None:
        ui.section("CERT-FR")
        ui.menu_item("1", "Avis et alertes")
        ui.menu_item("2", "Alertes seulement")
        ui.menu_item("0", "Retour")
        choice = ui.ask()
        if choice not in ("1", "2"):
            return
        days = _ask_int("nombre de jours", 7)
        bulletins = self.tk.certfr_recent(days, alertes=choice == "2")
        while True:
            ui.clear()
            console.print_certfr(bulletins, numbered=True)
            if not bulletins:
                ui.pause()
                return
            print(ui.c("\n  [n°] détail du bulletin · [0] retour", "gray"))
            pick = ui.ask("cert-fr")
            if pick in ("0", ""):
                return
            if pick.isdigit() and 1 <= int(pick) <= len(bulletins):
                self.bulletin_view(bulletins[int(pick) - 1])

    def bulletin_view(self, b: CertFrBulletin) -> None:
        ui.clear()
        ui.section(b.reference)
        console.print_bulletin(b)
        if b.cves:
            print(ui.c("\n  [n°] fiche d'une CVE du bulletin · [0] retour", "gray"))
            for index, cve in enumerate(b.cves[:20], 1):
                ui.menu_item(str(index), cve)
            choice = ui.ask("cert-fr")
            if choice.isdigit() and 1 <= int(choice) <= min(len(b.cves), 20):
                ui.info("Chargement de la fiche…")
                vulns, _ = self.tk.lookup([b.cves[int(choice) - 1]])
                self.vuln_view(vulns[0], "resume")
        else:
            ui.pause()

    # --- [6] CWE / [7] CVSS ----------------------------------------------------------------------------------

    def cwe(self) -> None:
        ui.section("FAIBLESSE CWE")
        print(ui.c("  un identifiant (79, CWE-89) ou un mot à chercher (injection, deserialization…)", "gray"))
        value = ui.ask("cwe")
        if not value:
            return
        catalog = self.tk.cwe_catalog()
        if re.fullmatch(r"(?i)(cwe-)?\d+", value):
            info = catalog.get(cwe_source.normalize_id(value))
            if info is None:
                raise ValueError(f"{value} absente du catalogue CWE {catalog.version}")
            ui.clear()
            console.print_cwe(info)
            ui.pause()
            return
        needle = value.lower()
        matches = sorted((i for i in catalog.entries.values() if needle in i.name.lower()),
                         key=lambda i: int(i.cwe_id.split("-")[1]))
        if not matches:
            ui.warn(f"Aucune faiblesse ne contient « {value} »")
            ui.pause()
            return
        while True:
            ui.clear()
            ui.section(f"CWE · {len(matches)} RÉSULTATS POUR « {value} »")
            for index, info in enumerate(matches[:30], 1):
                kind = ui.c(" (catégorie)", "gray") if info.kind == "category" else ""
                ui.menu_item(str(index), f"{info.cwe_id:<9} {info.name}{kind}", width=0)
            choice = ui.ask("cwe")
            if not choice.isdigit() or not 1 <= int(choice) <= min(len(matches), 30):
                return
            ui.clear()
            console.print_cwe(matches[int(choice) - 1])
            ui.pause()

    def cvss(self) -> None:
        ui.section("DÉCODER UN VECTEUR CVSS")
        print(ui.c("  ex. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "gray"))
        vector = ui.ask("cvss")
        if not vector:
            return
        explanation = explain(vector)
        if explanation is None:
            raise ValueError(f"vecteur CVSS illisible : {vector!r}")
        print()
        console.print_cvss_explanation(explanation, indent=2)
        ui.pause()

    # --- [8] Rapport / [9] État -------------------------------------------------------------------------------

    def open_report(self) -> None:
        path = self.tk.last_reports and next((p for p in self.tk.last_reports if p.suffix == ".html"), None)
        if not path:
            reports = sorted(Path(self.config.general.reports_dir).glob("veille_*.html"),
                             key=lambda p: p.stat().st_mtime)
            path = reports[-1] if reports else None
        if not path:
            ui.warn("Aucun rapport pour l'instant : lance un scan avec [1].")
            ui.pause()
            return
        ui.ok(f"Ouverture de {path}")
        if os.name == "nt":
            os.startfile(path)  # noqa: S606 — fichier local généré par l'outil
        else:
            webbrowser.open(path.resolve().as_uri())

    def status(self) -> None:
        ui.clear()
        ui.section("DIAGNOSTIC DES SOURCES")
        for r in run_checks(timeout=min(self.config.general.timeout, 15)):
            line = f"{r.name:<10} {ui.c(f'{r.latency * 1000:>6.0f} ms', 'gray')}  {r.detail}"
            (ui.ok if r.ok else ui.error)(line)
        key = "présente" if NvdClient.has_api_key() else ui.c("absente (5 req / 30 s)", "byellow")
        ui.info(f"Clé API NVD : {key}")
        from .cli import print_status  # évite un import circulaire

        print_status(self.config)
        ui.pause()


# --- Affichage compact ------------------------------------------------------------------------------


def _print_row(index: int, v: Vulnerability) -> None:
    score = ui.severity(v.cvss.severity if v.cvss else None, v.cvss_score)
    tags = []
    if v.is_exploited:
        tags.append(ui.c("KEV", "bold", "bred"))
    if v.kev and v.kev.ransomware:
        tags.append(ui.c("RW", "bold", "bmagenta"))
    tags.append(ui.c("FIX", "bgreen") if v.has_fix else ui.c("NOFIX", "red"))
    product = console.products_label(v, 38)
    print(f"  {ui.c('[', 'gray')}{ui.c(f'{index:>3}', 'bold', 'bgreen')}{ui.c(']', 'gray')} "
          f"{ui.c(v.cve_id.ljust(16), 'bold')} {score}  {ui.epss(v.epss_score)}  {product}  {' '.join(tags)}")


def _print_scan_summary(run, paths: list[Path]) -> None:
    selected = run.outcome.all
    critical = sum(1 for v in selected if v.cvss and v.cvss.severity == "CRITICAL")
    exploited = sum(v.is_exploited for v in selected)
    nofix = sum(not v.has_fix for v in selected)
    ui.section("RÉSULTAT")
    ui.menu_item("+", f"{len(selected)} failles retenues", f"sur {run.new_count} nouvelles", width=28)
    ui.menu_item("!", f"{critical} critiques (CVSS ≥ 9)", width=28)
    ui.menu_item("!", f"{exploited} exploitées activement", "CISA KEV", width=28)
    ui.menu_item("-", f"{nofix} sans correctif publié", width=28)
    if run.outcome.excluded_count:
        ui.menu_item("~", f"{run.outcome.excluded_count} écartées par les filtres", width=28)
    for path in paths:
        ui.ok(f"rapport : {path}")


def _ask_int(prompt: str, default: int) -> int:
    value = ui.ask(prompt, str(default))
    if not value.isdigit() or int(value) <= 0:
        raise ValueError(f"nombre invalide : {value!r}")
    return int(value)
