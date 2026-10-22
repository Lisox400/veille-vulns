import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import requests

from veille.cache import Cache
from veille.http import SourceError, fetch_cached
from veille.models import Vulnerability
from veille.pipeline import RunResult, commit, select_new, vulnerability_from_kev
from veille.sources.cisa_kev import parse_catalog

FIXTURE = Path(__file__).parent / "fixtures" / "kev_catalog.json"


class ParseCatalogTest(unittest.TestCase):
    def setUp(self):
        self.catalog = parse_catalog(FIXTURE.read_bytes())

    def test_entries(self):
        self.assertEqual(len(self.catalog), 2)  # l'entrée invalide est ignorée
        self.assertEqual(self.catalog.version, "2026.10.21")
        entry = self.catalog.get("CVE-2026-0001")
        self.assertTrue(entry.ransomware)
        self.assertEqual(entry.date_added, date(2026, 10, 20))
        self.assertEqual(entry.due_date, date(2026, 11, 10))
        self.assertEqual(entry.cwes, ("CWE-89",))
        self.assertFalse(self.catalog.get("CVE-2015-1234").ransomware)

    def test_added_since(self):
        ids = [e.cve_id for e in self.catalog.added_since(date(2026, 10, 1))]
        self.assertEqual(ids, ["CVE-2026-0001"])

    def test_invalid_content(self):
        for content in (b"<html>", b"{}", b'{"vulnerabilities": [{"x": 1}]}'):
            with self.assertRaises(ValueError):
                parse_catalog(content)

    def test_fallback_vulnerability(self):
        v = vulnerability_from_kev(self.catalog.get("CVE-2026-0001"))
        self.assertEqual(v.affected[0].product, "Example Server")
        self.assertEqual(v.cwe_ids, ["CWE-89"])


def fake_response(status, content=b"", headers=None):
    resp = mock.Mock(status_code=status, content=content, headers=headers or {})
    return resp


class FetchCachedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "kev.json"
        self.session = mock.Mock()

    def tearDown(self):
        self.tmp.cleanup()

    def fetch(self):
        return fetch_cached(self.session, "https://x", self.path, 5, "KEV", validate=parse_catalog)

    def test_download_then_conditional_then_offline(self):
        content = FIXTURE.read_bytes()
        self.session.get.return_value = fake_response(200, content, {"ETag": '"abc"'})
        self.assertFalse(self.fetch().stale)
        self.assertEqual(self.path.read_bytes(), content)

        self.session.get.return_value = fake_response(304)
        self.assertEqual(self.fetch().content, content)
        self.assertEqual(self.session.get.call_args.kwargs["headers"]["If-None-Match"], '"abc"')

        self.session.get.side_effect = requests.ConnectionError("down")
        result = self.fetch()
        self.assertTrue(result.stale)
        self.assertEqual(result.content, content)

    def test_invalid_download_keeps_previous_copy(self):
        content = FIXTURE.read_bytes()
        self.session.get.return_value = fake_response(200, content)
        self.fetch()
        self.session.get.return_value = fake_response(200, b"<html>maintenance</html>")
        result = self.fetch()
        self.assertTrue(result.stale)
        self.assertEqual(self.path.read_bytes(), content)

    def test_no_copy_and_offline_raises(self):
        self.session.get.side_effect = requests.ConnectionError("down")
        with self.assertRaises(SourceError):
            self.fetch()


class SelectNewTest(unittest.TestCase):
    def test_seen_cve_resurfaces_when_added_to_kev(self):
        catalog = parse_catalog(FIXTURE.read_bytes())
        now = datetime(2026, 10, 22, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as tmp, Cache(Path(tmp) / "v.db") as cache:
            # Lancement 1 : la CVE est publiée, pas encore dans le KEV.
            run1 = RunResult(now - timedelta(days=5), now - timedelta(days=4),
                             fetched=[Vulnerability("CVE-2026-0001")], nvd_ok=True, kev_ok=True)
            self.assertEqual(len(select_new(run1, cache)), 1)
            commit(cache, run1, now, 1)
            self.assertEqual(select_new(run1, cache), [])

            # Lancement 2 : elle vient d'être ajoutée au KEV → elle doit ressortir.
            v = Vulnerability("CVE-2026-0001", kev=catalog.get("CVE-2026-0001"), newly_exploited=True)
            run2 = RunResult(now - timedelta(days=2), now, fetched=[v], nvd_ok=True, kev_ok=True)
            self.assertEqual(select_new(run2, cache), [v])
            commit(cache, run2, now, 1)

            # Lancement 3 : déjà signalée comme exploitée → plus affichée.
            self.assertEqual(select_new(run2, cache), [])
            self.assertEqual(select_new(run2, cache, show_seen=True), [v])


if __name__ == "__main__":
    unittest.main()
