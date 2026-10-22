import tempfile
import unittest
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

from veille.config import FilterConfig
from veille.filtering import apply_filters, describe, prefilter
from veille.models import (
    AffectedProduct, CertFrBulletin, CvssInfo, CweInfo, CweMitigation, KevEntry, PackageFix,
    Reference, SourceStatus, Vulnerability,
)
from veille.report import html, markdown
from veille.report.builder import build_report, write_report

KEV = KevEntry("CVE-K", "Ivanti", "Connect Secure", "Ivanti Connect Secure RCE", date(2026, 10, 20),
               required_action="Apply updates.", ransomware=True)


def vuln(cve, score=None, kev=None, text="", products=(), cpes=()):
    return Vulnerability(
        cve,
        description=text,
        cvss=CvssInfo("3.1", score, "CRITICAL" if score and score >= 9 else "MEDIUM",
                      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") if score is not None else None,
        kev=kev,
        affected=[AffectedProduct(v, p) for v, p in products],
        cpes=list(cpes),
    )


class FilterTest(unittest.TestCase):
    def setUp(self):
        self.vulns = [
            vuln("CVE-1", 9.8, text="RCE in Fortinet FortiOS"),
            vuln("CVE-2", 5.0, text="XSS in a WordPress plugin"),
            vuln("CVE-3", 4.0, kev=KEV, text="Ivanti bug"),
            vuln("CVE-4", None, text="unscored openssl issue"),
            vuln("CVE-5", 8.1, cpes=["cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*"]),
        ]

    def ids(self, outcome):
        return [v.cve_id for v in outcome.kept], [v.cve_id for v in outcome.unscored]

    def test_no_filter(self):
        outcome = apply_filters(self.vulns, FilterConfig())
        self.assertEqual(self.ids(outcome), (["CVE-3", "CVE-1", "CVE-5", "CVE-2"], ["CVE-4"]))

    def test_min_cvss_keeps_exploited_and_unscored(self):
        outcome = apply_filters(self.vulns, FilterConfig(min_cvss=7))
        self.assertEqual(self.ids(outcome), (["CVE-3", "CVE-1", "CVE-5"], ["CVE-4"]))
        self.assertEqual(outcome.excluded, Counter({"CVSS < 7": 1}))
        strict = apply_filters(self.vulns, FilterConfig(min_cvss=7, always_keep_exploited=False,
                                                        include_unscored=False))
        self.assertEqual(self.ids(strict), (["CVE-1", "CVE-5"], []))

    def test_only_exploited(self):
        outcome = apply_filters(self.vulns, FilterConfig(only_exploited=True))
        self.assertEqual(self.ids(outcome), (["CVE-3"], []))

    def test_keywords(self):
        cfg = FilterConfig(keywords=("fortinet", "exchange server", "Connect Secure"))
        self.assertEqual(self.ids(apply_filters(self.vulns, cfg)), (["CVE-3", "CVE-1", "CVE-5"], []))
        cfg = FilterConfig(exclude_keywords=("wordpress plugin",))
        outcome = apply_filters(self.vulns, cfg)
        self.assertNotIn("CVE-2", self.ids(outcome)[0])
        self.assertEqual(outcome.excluded, Counter({"mot-clé exclu « wordpress plugin »": 1}))

    def test_keyword_not_matching_inside_word(self):
        cfg = FilterConfig(keywords=("ssl",))
        self.assertEqual(self.ids(apply_filters(self.vulns, cfg)), ([], []))  # « openssl » ≠ « ssl »

    def test_prefilter_ignores_keywords(self):
        kept, excluded = prefilter(self.vulns, FilterConfig(min_cvss=7, keywords=("nothing",)))
        self.assertEqual([v.cve_id for v in kept], ["CVE-1", "CVE-3", "CVE-4", "CVE-5"])
        outcome = apply_filters(kept, FilterConfig(min_cvss=7, keywords=("nothing",)), excluded)
        self.assertEqual(outcome.excluded_count, 5)

    def test_describe(self):
        lines = describe(FilterConfig(min_cvss=7, keywords=("a",), only_exploited=False))
        self.assertEqual(lines[0], "CVSS ≥ 7 (sauf failles exploitées, toujours conservées)")


class ReportTest(unittest.TestCase):
    def build(self):
        evil = '<script>alert(1)</script> | *bold* [x](javascript:alert(1))'
        cwe = CweInfo("CWE-79", "XSS", description="Improper neutralization.",
                      mitigations=(CweMitigation(("Implementation",), "Output Encoding", "Encode output."),))
        exploited = vuln("CVE-2026-1", 9.8, kev=KEV, text=evil, products=[("acme", "box")])
        exploited.cwes = [cwe]
        exploited.cwe_ids = ["CWE-79"]
        exploited.references = [Reference("https://acme/patch", tags=("Patch",)),
                                Reference("javascript:alert(1)", tags=("Vendor Advisory",))]
        exploited.osv_fixes = [PackageFix("PyPI", "box", ("1.2",))]
        exploited.certfr = [CertFrBulletin("CERTFR-2026-AVI-1", "avis", "Vuln <b>Acme</b>",
                                           "https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1/",
                                           solution="## Solution\n\nAppliquer **le correctif**.")]
        other = vuln("CVE-2026-2", None, text="pending")
        other.cwes = [cwe]
        outcome = apply_filters([exploited, other], FilterConfig())
        now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
        statuses = [SourceStatus("NVD", True, count=2), SourceStatus("OSV", False, message="timeout")]
        return build_report(outcome, statuses, ["CVSS ≥ 7"], now, now, 10, 2, now)

    def test_summary(self):
        data = self.build()
        self.assertEqual((len(data.all), data.critical, data.exploited, data.ransomware, data.without_fix),
                         (2, 1, 1, 1, 1))
        self.assertEqual([(c.cwe_id, n) for c, n in data.appendix], [("CWE-79", 2)])

    def test_html_escapes_untrusted_content(self):
        page = html.render(self.build())
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn('href="javascript:', page)
        self.assertNotIn("<b>Acme</b>", page)
        self.assertIn("Appliquer le correctif.", page)
        self.assertIn("indisponible : timeout", page)
        self.assertIn("href='#cwe-79'", page)

    def test_markdown_content(self):
        md = markdown.render(self.build())
        self.assertNotIn("<script>", md)
        self.assertNotRegex(md, r"(?<!\\)\]\(javascript:")  # crochets échappés : pas de lien
        self.assertNotIn("](javascript:alert(1))\n", md.replace("\\]", ""))  # URL non-http jamais en lien
        self.assertIn("\\| \\*bold\\*", md)  # caractères Markdown neutralisés
        for expected in ("## Résumé", "#### 1. Informations générales", "#### 2. Mode d'exploitation",
                         "#### 3. Correction", "**OUI**", "\\[PyPI\\] box : 1.2", "Aucun correctif publié",
                         "## Failles sans score CVSS", "## Annexe", "❌ **OSV**"):
            self.assertIn(expected, md)

    def test_write_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_report(self.build(), Path(tmp) / "out", ("md", "html"))
            self.assertEqual([p.name for p in paths], ["veille_2026-10-22_1200.md", "veille_2026-10-22_1200.html"])
            self.assertTrue(all(p.stat().st_size > 1000 for p in paths))


if __name__ == "__main__":
    unittest.main()
