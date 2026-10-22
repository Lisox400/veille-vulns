import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from veille.sources.nvd import format_date, parse_cve, split_window

FIXTURE = Path(__file__).parent / "fixtures" / "nvd_page.json"


def load():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return [parse_cve(item["cve"]) for item in data["vulnerabilities"]]


class ParseCveTest(unittest.TestCase):
    def setUp(self):
        self.full, self.minimal = load()

    def test_general_fields(self):
        v = self.full
        self.assertEqual(v.cve_id, "CVE-2026-0001")
        self.assertEqual(v.published, datetime(2026, 10, 21, 14, 15, 7, 123000, tzinfo=timezone.utc))
        self.assertTrue(v.description.startswith("SQL injection"))  # anglais préféré

    def test_cvss_prefers_v31_primary(self):
        self.assertEqual(self.full.cvss.version, "3.1")
        self.assertEqual(self.full.cvss.score, 9.8)
        self.assertTrue(self.full.cvss.primary)
        self.assertEqual(len(self.full.cvss_all), 3)

    def test_cvss_v2_severity_from_metric(self):
        self.assertEqual(self.minimal.cvss.version, "2.0")
        self.assertEqual(self.minimal.cvss.severity, "MEDIUM")

    def test_cwes_primary_first_and_placeholders_dropped(self):
        self.assertEqual(self.full.cwe_ids, ["CWE-89", "CWE-20"])

    def test_affected_products(self):
        by_product = {(a.vendor, a.product): a.versions for a in self.full.affected}
        self.assertEqual(by_product[("example corp", "example server")], ("≥ 2.0, < 2.4.1", "3.0"))
        self.assertEqual(by_product[("other:vendor", "tool")], ("version non précisée",))
        self.assertNotIn(("linux", "linux kernel"), by_product)  # vulnerable = false
        self.assertEqual(len(self.full.cpes), 3)

    def test_references_and_exploit_flag(self):
        self.assertTrue(self.full.has_exploit_reference)
        self.assertEqual(self.full.references[0].tags, ("Vendor Advisory", "Patch"))
        self.assertFalse(self.minimal.has_exploit_reference)

    def test_minimal_entry(self):
        v = self.minimal
        self.assertEqual(v.description, "Legacy bug.")
        self.assertEqual((v.affected, v.cwe_ids, v.references), ([], [], []))


class WindowTest(unittest.TestCase):
    def test_split_window_120_days(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        chunks = list(split_window(start, start + timedelta(days=250)))
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0][1] - chunks[0][0], timedelta(days=120))
        self.assertEqual(chunks[-1][1], start + timedelta(days=250))

    def test_format_date_utc(self):
        dt = datetime(2026, 10, 22, 12, 0, tzinfo=timezone(timedelta(hours=2)))
        self.assertEqual(format_date(dt), "2026-10-22T10:00:00.000+00:00")


if __name__ == "__main__":
    unittest.main()
