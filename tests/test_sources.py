import unittest
from datetime import date, datetime, timezone

from veille.filtering import prioritize
from veille.http import SourceError
from veille.models import CertFrBulletin, CvssInfo, EpssScore, KevEntry, PackageFix, Reference, Vulnerability
from veille.report.console import markdown_to_text
from veille.sources import fetch_each
from veille.sources.certfr import clean_markdown, extract_solution, parse_bulletin
from veille.sources.cveorg import parse_record, version_label
from veille.sources.epss import parse_item
from veille.sources.osv import merge_fixes, parse_record as parse_osv


class EpssTest(unittest.TestCase):
    def test_parse_item(self):
        s = parse_item({"cve": "CVE-1", "epss": "0.97", "percentile": "0.999", "date": "2026-10-22"})
        self.assertEqual((s.score, s.percentile, s.date), (0.97, 0.999, date(2026, 10, 22)))


class OsvTest(unittest.TestCase):
    RECORD = {
        "id": "GHSA-xxxx",
        "affected": [
            {"package": {"ecosystem": "Maven", "name": "org.apache:log4j-core"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]},
                        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]},
            {"package": {"ecosystem": "Maven", "name": "org.apache:log4j-core"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.3.1"}]}]},
            {"package": {"ecosystem": "PyPI", "name": "vulnlib"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.0"}]}]},
            {"ranges": [{"type": "GIT", "events": [{"fixed": "def"}]}]},
        ],
    }

    def test_parse_and_merge(self):
        fixes = merge_fixes(parse_osv(self.RECORD))
        self.assertEqual(len(fixes), 2)
        self.assertEqual(fixes[0].fixed, ("2.15.0", "2.3.1"))  # commits GIT ignorés
        self.assertEqual(fixes[1].fixed, ())                   # aucune version corrigée


class CveOrgTest(unittest.TestCase):
    def test_version_label(self):
        self.assertEqual(version_label({"version": "10.2.0", "lessThan": "10.2.9-h1"}), "≥ 10.2.0, < 10.2.9-h1")
        self.assertEqual(version_label({"version": "0", "lessThan": "1.6.20"}), "< 1.6.20")
        self.assertEqual(version_label({"version": "n/a", "lessThanOrEqual": "3.1"}), "≤ 3.1")
        self.assertEqual(version_label({"version": "4.1.2"}), "4.1.2")
        self.assertEqual(version_label({"version": "unspecified"}), "version non précisée")

    def test_parse_record(self):
        data = {"containers": {"cna": {"affected": [
            {"vendor": "Palo Alto Networks", "product": "PAN-OS", "defaultStatus": "unaffected", "versions": [
                {"version": "9.0.0", "status": "unaffected"},
                {"version": "10.2.0", "lessThan": "10.2.9-h1", "status": "affected",
                 "changes": [{"at": "10.2.9-h1", "status": "unaffected"}]},
                {"version": "0", "lessThan": "11.0.4", "status": "affected"},
                {"version": "abc", "lessThan": "def", "status": "affected", "versionType": "git"},
            ]},
            {"vendor": "n/a", "product": "n/a"},
        ]}}}
        record = parse_record(data)
        self.assertEqual(len(record.affected), 1)
        self.assertEqual(record.affected[0].versions, ("≥ 10.2.0, < 10.2.9-h1", "< 11.0.4"))
        self.assertEqual(record.fixed_versions, ["PAN-OS : 10.2.9-h1", "PAN-OS : 11.0.4"])

    def test_adp_fallback(self):
        data = {"containers": {
            "cna": {"affected": [{"vendor": "n/a", "product": "n/a"}]},
            "adp": [{"affected": [{"vendor": "acme", "product": "box", "defaultStatus": "affected"}]}],
        }}
        record = parse_record(data)
        self.assertEqual(record.affected[0].product, "box")
        self.assertEqual(record.affected[0].versions, ("toutes versions",))


class CertFrTest(unittest.TestCase):
    CONTENT = (
        "## Risques\n\nExécution de code\n\n"
        "## Contournement provisoire\n\n**\\[Mise à jour\\] Désactiver\nle service** <span style=\"x\">ici</span>\n\n"
        "## Solutions\n\nAppliquer le correctif &amp; redémarrer.\n\n"
        "## Documentation\n\n- lien\n"
    )

    def test_extract_solution(self):
        solution = extract_solution(self.CONTENT)
        self.assertIn("## Contournement provisoire", solution)
        self.assertIn("## Solutions", solution)
        self.assertNotIn("Risques", solution)
        self.assertNotIn("Documentation", solution)
        self.assertNotIn("<span", solution)
        self.assertIn("correctif & redémarrer", solution)

    def test_markdown_to_text(self):
        text = markdown_to_text(clean_markdown("**\\[Mise à jour\\] Désactiver\nle service** et *ceci* [lien](https://x)"))
        self.assertEqual(text, "[Mise à jour] Désactiver\nle service et ceci lien (https://x)")

    def test_parse_bulletin(self):
        data = {
            "reference": "CERTFR-2026-AVI-0001", "title": "Vulnérabilité dans Acme",
            "affected_systems": [{"description": "Box versions antérieures à 2.0", "product": {"name": "Box"}}],
            "cves": [{"name": "CVE-2026-1"}], "content": self.CONTENT,
            "vendor_advisories": [{"title": "Bulletin Acme", "url": "https://acme/1"}],
            "revisions": [{"revision_date": "2026-10-01T00:00:00.000000"}],
        }
        b = parse_bulletin(data, "avis")
        self.assertEqual(b.url, "https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-0001/")
        self.assertEqual(b.cves, ("CVE-2026-1",))
        self.assertEqual(b.affected_systems, ("Box versions antérieures à 2.0",))
        self.assertEqual(b.date, datetime(2026, 10, 1))
        self.assertTrue(b.solution)


class FetchEachTest(unittest.TestCase):
    def test_partial_errors(self):
        def func(x):
            if x == 2:
                raise SourceError("boom")
            return [] if x == 3 else x * 10
        results, errors = fetch_each("t", [1, 2, 3, 1], func, workers=2)
        self.assertEqual(results, {1: 10})  # résultats vides écartés, doublons ignorés
        self.assertEqual(len(errors), 1)

    def test_source_down_aborts(self):
        def func(x):
            raise SourceError("down")
        with self.assertRaises(SourceError):
            fetch_each("t", range(50), func, workers=1)


class PriorityAndFixTest(unittest.TestCase):
    def test_prioritize_kev_then_epss_then_cvss(self):
        kev = KevEntry("CVE-K", "v", "p", "n", date(2026, 1, 1))
        def vuln(cve, epss=None, cvss=None, exploited=False):
            return Vulnerability(
                cve,
                epss=EpssScore(epss, 0.5) if epss is not None else None,
                cvss=CvssInfo("3.1", cvss, "HIGH", "") if cvss is not None else None,
                kev=kev if exploited else None,
            )
        vulns = [vuln("A", 0.1, 9.8), vuln("B", 0.5, 5.0), vuln("C", None, 10.0),
                 vuln("D", 0.01, 4.0, exploited=True), vuln("E", 0.1, 7.0)]
        self.assertEqual([v.cve_id for v in prioritize(vulns)], ["D", "B", "A", "E", "C"])

    def test_has_fix(self):
        self.assertFalse(Vulnerability("X", references=[Reference("u", tags=("Vendor Advisory",))]).has_fix)
        self.assertTrue(Vulnerability("X", references=[Reference("u", tags=("Patch",))]).has_fix)
        self.assertTrue(Vulnerability("X", osv_fixes=[PackageFix("PyPI", "p", ("1.2",))]).has_fix)
        self.assertFalse(Vulnerability("X", osv_fixes=[PackageFix("PyPI", "p", ())]).has_fix)
        self.assertTrue(Vulnerability("X", fixed_versions=["P : 1.2"]).has_fix)
        self.assertTrue(Vulnerability("X", certfr=[CertFrBulletin("R", "avis", "t", "u", solution="x")]).has_fix)


if __name__ == "__main__":
    unittest.main()
