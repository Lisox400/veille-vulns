"""Tests d'affichage : chaque fonction de rendu et les parcours du menu interactif
sont exécutés sur des données d'exemple (hors ligne)."""

import contextlib
import io
import unittest
from datetime import date, datetime, timezone
from unittest import mock

from veille import ui
from veille.config import Config, FilterConfig, GeneralConfig
from veille.filtering import apply_filters
from veille.interactive import Menu
from veille.models import (
    AffectedProduct, CertFrBulletin, CvssInfo, EpssScore, KevEntry, PackageFix, Reference, Vulnerability,
)
from veille.report import console
from veille.sources.cwe import parse_xml

from .test_enrichment import CWE_XML

KEV = KevEntry("CVE-2026-0001", "Acme", "Box", "Acme Box RCE", date(2026, 10, 20),
               required_action="Apply updates.", due_date=date(2026, 11, 10), ransomware=True)
BULLETIN = CertFrBulletin(
    "CERTFR-2026-AVI-0001", "avis", "Vulnérabilité dans Acme Box", "https://cert.cyber.gouv.fr/avis/x/",
    date=datetime(2026, 10, 21, tzinfo=timezone.utc), risks=("Exécution de code",),
    affected_systems=("Box versions antérieures à 2.0",), solution="## Solution\n\nMettre à jour.",
    vendor_advisories=(("Bulletin Acme", "https://acme/1"),), cves=("CVE-2026-0001",),
)


def sample_vulns():
    catalog = parse_xml(CWE_XML)
    full = Vulnerability(
        "CVE-2026-0001", published=datetime(2026, 10, 20, tzinfo=timezone.utc), status="Analyzed",
        description="SQL injection in Acme Box.",
        cvss=CvssInfo("3.1", 9.8, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        cwe_ids=["CWE-89"], cwes=[catalog.get("CWE-89")],
        references=[Reference("https://acme/patch", tags=("Patch",)), Reference("https://poc", tags=("Exploit",))],
        affected=[AffectedProduct("acme", "box", ("< 2.0",))], affected_source="NVD",
        fixed_versions=["Box : 2.0"], kev=KEV, newly_exploited=True, epss=EpssScore(0.42, 0.97),
        osv_fixes=[PackageFix("PyPI", "acme-box", ("2.0",))], certfr=[BULLETIN],
    )
    bare = Vulnerability("CVE-2026-0002", description="Pending analysis.")
    return [full, bare]


def quiet():
    stack = contextlib.ExitStack()
    out = io.StringIO()
    stack.enter_context(contextlib.redirect_stdout(out))
    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
    return stack, out


class ConsoleTest(unittest.TestCase):
    def test_every_printer_runs(self):
        full, bare = sample_vulns()
        outcome = apply_filters([full, bare], FilterConfig())
        stack, out = quiet()
        with stack:
            for v in (full, bare):
                console.print_detail(v)
                for name in console.SECTIONS:
                    console.print_detail(v, [name])
            console.print_scan(outcome, 10, 2, 15, ["CVSS ≥ 7"])
            console.print_kev([KEV], {"CVE-2026-0001": EpssScore(0.42, 0.97)})
            console.print_kev([KEV], {}, numbered=True)
            console.print_kev([], {})
            console.print_certfr([BULLETIN])
            console.print_certfr([BULLETIN], numbered=True)
            console.print_epss(["CVE-2026-0001", "CVE-2099-1"], {"CVE-2026-0001": EpssScore(0.42, 0.97)})
            console.print_cwe(full.cwes[0])
        text = out.getvalue()
        for expected in ("Correctif disponible", "Aucun correctif publié", "Box : 2.0", "acme-box",
                         "Mettre à jour.", "CERTFR-2026-AVI-0001", "Scénario critique", "n/a"):
            self.assertIn(expected, text)


def make_menu():
    config = Config(general=GeneralConfig(), filters=FilterConfig())
    menu = Menu(config)
    menu.tk.cwe_catalog = lambda: parse_xml(CWE_XML)
    menu.tk.kev_recent = lambda days, *a, **k: ([KEV], {})
    menu.tk.certfr_recent = lambda days, *a, **k: [BULLETIN]
    menu.tk.lookup = lambda ids: (sample_vulns()[:1], [])
    return menu


def run_menu(menu, inputs, action=None):
    stack, out = quiet()
    with stack, mock.patch("builtins.input", side_effect=inputs):
        if action:
            action()
        else:
            menu.run()
    return out.getvalue()


class MenuTest(unittest.TestCase):
    def test_main_menu_and_quit(self):
        text = run_menu(make_menu(), ["9x", "0"])
        self.assertIn("Nouvelles vulnérabilités", text)
        self.assertIn("lisox", text)

    def test_ctrl_c_quits(self):
        stack, _ = quiet()
        with stack, mock.patch("builtins.input", side_effect=KeyboardInterrupt):
            self.assertEqual(make_menu().run(), 0)

    def test_browse_and_vuln_sections(self):
        menu = make_menu()
        # fiche n°1 → section patch → tout afficher → [Entrée] → retour fiche → retour liste
        text = run_menu(menu, ["1", "3", "6", "", "0", "0"], lambda: menu.browse(sample_vulns(), "TEST"))
        self.assertIn("PATCHS & CORRECTIFS", text)
        self.assertIn("COMMENT ELLE EST EXPLOITÉE", text)

    def test_cve_lookup_patch(self):
        text = run_menu(make_menu(), ["3", "2026-0001", "0", "0"])
        self.assertIn("Box : 2.0", text)

    def test_kev_certfr_cwe_cvss(self):
        menu = make_menu()
        text = run_menu(menu, [
            "4", "7", "1", "0", "0",            # KEV : 7 jours → fiche n°1 → retour → retour
            "5", "1", "7", "1", "0", "0",       # CERT-FR → bulletin n°1 → retour
            "6", "89", "",                      # CWE-89
            "6", "sql", "1", "", "0",           # recherche « sql » → n°1
            "7", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "",
            "7", "pas un vecteur", "",          # erreur affichée, retour au menu
            "0",
        ])
        for expected in ("CISA KEV", "CERTFR-2026-AVI-0001", "SQL Injection", "Scénario critique"):
            self.assertIn(expected, text)

    def test_invalid_cve_shows_error(self):
        stack, _ = quiet()
        with stack, mock.patch("builtins.input", side_effect=["2", "pas-une-cve", "", "0"]), \
                mock.patch.object(ui, "error") as error:
            make_menu().run()
        error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
