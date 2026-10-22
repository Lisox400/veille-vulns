import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from veille.cache import Cache
from veille.cli import parse_since
from veille.config import ConfigError, load_config
from veille.models import Vulnerability


class CacheTest(unittest.TestCase):
    def test_seen_and_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
            with Cache(Path(tmp) / "sub" / "v.db") as cache:
                self.assertIsNone(cache.last_window_end())
                cache.mark_seen([Vulnerability("CVE-1"), Vulnerability("CVE-2")], now)
                self.assertEqual(cache.seen_ids(["CVE-1", "CVE-3"]), {"CVE-1"})
                cache.record_run(now, now - timedelta(days=1), now, True, 2)
                cache.record_run(now, now, now + timedelta(hours=5), False, 0)
                # Un lancement en échec n'avance pas la fenêtre.
                self.assertEqual(cache.last_window_end(), now)


class ConfigTest(unittest.TestCase):
    def write(self, tmp, text):
        path = Path(tmp) / "config.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_load_and_resolve_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = load_config(self.write(tmp, '[filters]\nmin_cvss = 7\nkeywords = ["OpenSSL", " "]\n'))
            self.assertEqual(cfg.filters.min_cvss, 7.0)
            self.assertEqual(cfg.filters.keywords, ("OpenSSL",))
            self.assertEqual(cfg.general.data_dir, Path(tmp).resolve() / "data")

    def test_invalid_values(self):
        cases = (
            "[filters]\nmin_cvss = 11\n",
            '[filters]\nonly_exploited = "yes"\n',
            "x = [",
            '[filters]\nkeywords = "a"\n',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for text in cases:
                with self.assertRaises(ConfigError, msg=text):
                    load_config(self.write(tmp, text))


class SinceTest(unittest.TestCase):
    def test_parse_since(self):
        now = datetime(2026, 10, 22, tzinfo=timezone.utc)
        self.assertEqual(parse_since("48h", now), now - timedelta(hours=48))
        self.assertEqual(parse_since("7d", now), now - timedelta(days=7))
        self.assertEqual(parse_since("2026-10-01", now), datetime(2026, 10, 1, tzinfo=timezone.utc))
        with self.assertRaises(ValueError):
            parse_since("hier", now)


if __name__ == "__main__":
    unittest.main()
