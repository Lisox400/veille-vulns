"""Diagnostic : teste rapidement la disponibilité de chaque source."""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import requests

from .http import USER_AGENT
from .sources import certfr, cisa_kev, cveorg, cwe, epss, nvd, osv

PROBE_CVE = "CVE-2021-44228"


@dataclass(frozen=True)
class CheckResult:
    name: str
    url: str
    ok: bool
    latency: float
    detail: str


def _checks() -> list[tuple[str, str, str, dict]]:
    """(nom, méthode, url, paramètres)"""
    return [
        ("NVD", "GET", nvd.API_URL, {"cveId": PROBE_CVE}),
        ("CISA KEV", "HEAD", cisa_kev.CATALOG_URL, {}),
        ("EPSS", "GET", epss.API_URL, {"cve": PROBE_CVE}),
        ("CERT-FR", "GET", certfr.FEEDS["avis"], {}),
        ("OSV", "GET", osv.API_URL + PROBE_CVE, {}),
        ("CVE.org", "GET", cveorg.API_URL + PROBE_CVE, {}),
        ("CWE MITRE", "HEAD", cwe.CATALOG_URL, {}),
    ]


def run_checks(timeout: int = 15) -> list[CheckResult]:
    def probe(check: tuple[str, str, str, dict]) -> CheckResult:
        name, method, url, params = check
        headers = {"User-Agent": USER_AGENT}
        if name == "NVD" and os.environ.get(nvd.API_KEY_ENV):
            headers["apiKey"] = os.environ[nvd.API_KEY_ENV]
        start = time.monotonic()
        try:
            resp = requests.request(method, url, params=params, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            return CheckResult(name, url, False, time.monotonic() - start, exc.__class__.__name__)
        latency = time.monotonic() - start
        return CheckResult(name, url, resp.status_code == 200, latency, f"HTTP {resp.status_code}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(probe, _checks()))
