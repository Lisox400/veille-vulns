"""Affichage des résultats dans le terminal."""

from __future__ import annotations

import re
import textwrap
from collections.abc import Iterable

from .. import ui
from ..enrichment import cvss
from ..enrichment import cwe as cwe_fr
from ..filtering import FilterOutcome
from ..models import CertFrBulletin, CweInfo, CweMitigation, EpssScore, KevEntry, SourceStatus, Vulnerability
from .text import markdown_to_text, shorten as _shorten, solution_paragraphs

MAX_REFS = 8
SOLUTION_PREVIEW = 3  # paragraphes de la solution CERT-FR montrés dans la section Patchs


def _pad(text: str, size: int) -> str:
    """Tronque/complète avant colorisation (les codes ANSI faussent len())."""
    text = " ".join(str(text).split())
    return text[: size - 1] + "…" if len(text) > size else text.ljust(size)


def _wrap(text: str, indent: int, width: int | None = None) -> str:
    width = width or ui.width()
    prefix = " " * indent
    return textwrap.fill(" ".join(text.split()), width=width - 2, initial_indent=prefix, subsequent_indent=prefix)


def _wrap_paragraphs(text: str, indent: int) -> str:
    paragraphs = [p for p in re.split(r"\n\s*\n|\n(?=\s*[-*•] )", text) if p.strip()]
    return "\n".join(_wrap(p, indent) for p in paragraphs)


def products_label(v: Vulnerability, size: int) -> str:
    if not v.affected:
        return ui.c(_pad("produit non renseigné", size), "gray")
    label = ", ".join(f"{a.vendor} / {a.product}" for a in v.affected[:2])
    if len(v.affected) > 2:
        label += f" +{len(v.affected) - 2}"
    return _pad(label, size)


def flags(v: Vulnerability) -> str:
    parts = [
        ui.c("KEV", "bold", "bred") if v.is_exploited else ui.c("···", "gray"),
        ui.c("RW", "bold", "bmagenta") if v.kev and v.kev.ransomware else ui.c("··", "gray"),
        ui.c("EXP", "byellow") if v.has_exploit_reference else ui.c("···", "gray"),
        ui.c("FR", "bblue") if v.certfr else ui.c("··", "gray"),
        ui.c("FIX  ", "bgreen") if v.has_fix else ui.c("NOFIX", "red"),
    ]
    return " ".join(parts)


# --- Statuts des sources ----------------------------------------------------------


def print_statuses(statuses: Iterable[SourceStatus]) -> None:
    for s in statuses:
        name = _pad(s.name, 18)
        if s.ok:
            detail = f"{s.count} entrées en {s.duration:.1f}s"
            if s.message:
                ui.warn(f"{name} {detail} — {s.message}")
            else:
                ui.ok(f"{name} {ui.c(detail, 'gray')}")
        else:
            ui.error(f"{name} {ui.c('INDISPONIBLE', 'bold', 'bred')} — {s.message}")


# --- scan ---------------------------------------------------------------------------


def print_scan(outcome: FilterOutcome, total: int, new_count: int, limit: int, filters: list[str]) -> None:
    selected = outcome.all
    exploited = sum(v.is_exploited for v in selected)
    critical = sum(1 for v in selected if v.cvss and v.cvss.severity == "CRITICAL")
    nofix = sum(not v.has_fix for v in selected)
    ransomware = sum(1 for v in selected if v.kev and v.kev.ransomware)

    ui.section("RÉSUMÉ")
    print(
        f"  {ui.c(total, 'bold')} CVE récupérées · {ui.c(new_count, 'bold')} nouvelles · "
        f"{ui.c(len(selected), 'bold', 'bcyan')} retenues après filtres"
    )
    print(
        f"  {ui.c(critical, 'bold', 'bred')} critiques · {ui.c(exploited, 'bold', 'bred')} exploitées (KEV) · "
        f"{ui.c(ransomware, 'bold', 'bmagenta')} ransomware · {ui.c(nofix, 'bold', 'yellow')} sans correctif · "
        f"{ui.c(len(outcome.unscored), 'bold')} sans score CVSS"
    )
    if filters:
        print(ui.c("  filtres : " + " | ".join(filters), "gray"))
    for reason, count in outcome.excluded.most_common():
        print(ui.c(f"  écartées ({reason}) : {count}", "gray"))
    if not selected:
        print(ui.c("\n  Rien de nouveau qui corresponde aux critères.", "gray"))
        return

    if outcome.kept:
        _print_table(outcome.kept, limit, "VULNÉRABILITÉS", start=1)
    if outcome.unscored:
        _print_table(outcome.unscored, min(limit, 10) if limit > 0 else 0, "SANS SCORE CVSS",
                     start=len(outcome.kept) + 1)
    print(ui.c("\n  KEV exploitée · RW ransomware · EXP exploit public référencé · FR avis CERT-FR · "
               "FIX correctif attesté", "gray"))


def _print_table(vulns: list[Vulnerability], limit: int, title: str, start: int) -> None:
    shown = vulns if limit <= 0 else vulns[:limit]
    ui.section(f"{title} · TOP {len(shown)}/{len(vulns)}" if len(shown) < len(vulns) else f"{title} · {len(vulns)}")
    desc_width = ui.width() - 8
    header = f"  {'#':>4}  {'CVE':<17} {'CVSS':<9}  {'EPSS':>6}  {'KEV RW EXP FR FIX':<19}  PRODUIT"
    print(ui.c(header, "bold", "gray"))
    for rank, v in enumerate(shown, start):
        score = ui.severity(v.cvss.severity if v.cvss else None, v.cvss_score)
        print(
            f"  {ui.c(f'{rank:>4}', 'gray')}  {ui.c(_pad(v.cve_id, 17), 'bold')} {score}  "
            f"{ui.epss(v.epss_score)}  {flags(v)}  {products_label(v, 40)}"
        )
        print(ui.c(f"        └ {_pad(v.description or '(pas de description)', desc_width - 5)}", "gray"))
    if len(shown) < len(vulns):
        print(ui.c(f"\n  … {len(vulns) - len(shown)} autres dans le rapport (option -n 0 pour tout afficher)", "gray"))


# --- fiche d'une CVE, découpée en sections ------------------------------------------------

SECTIONS = {
    "resume": "Résumé & produits touchés",
    "exploit": "Comment elle est exploitée",
    "patch": "Patchs & correctifs",
    "prevention": "Prévention (type de faille)",
    "certfr": "Avis CERT-FR",
}


def print_card(v: Vulnerability) -> None:
    """En-tête compact : l'essentiel en 4 lignes."""
    ui.section(v.cve_id)
    score = ui.severity(v.cvss.severity, v.cvss.score) if v.cvss else ui.c("CVSS n/a", "gray")
    tags = []
    if v.is_exploited:
        tags.append(ui.tag("EXPLOITÉE", "bred"))
    if v.kev and v.kev.ransomware:
        tags.append(ui.tag("RANSOMWARE", "bmagenta"))
    if v.has_exploit_reference:
        tags.append(ui.tag("EXPLOIT PUBLIC", "byellow"))
    if v.certfr:
        tags.append(ui.tag("CERT-FR", "bblue"))
    tags.append(ui.tag("CORRECTIF", "bgreen") if v.has_fix else ui.tag("SANS CORRECTIF", "red"))
    print(f"  {score}   EPSS {ui.epss(v.epss_score).strip()}   {' '.join(tags)}")
    published = v.published.strftime("%Y-%m-%d") if v.published else "?"
    print(f"  {products_label(v, 60).rstrip()}   {ui.c(f'publiée le {published}', 'gray')}")
    if v.description:
        print(ui.c(_wrap(_shorten(v.description, 240), 2), "gray"))


def _title(number: str, text: str, color: str) -> None:
    print(f"\n  {ui.c(f'[{number}]', 'bold', color)} {ui.c(text.upper(), 'bold', color)}")


def print_general(v: Vulnerability) -> None:
    _title("1", SECTIONS["resume"], "bcyan")
    label = lambda text: ui.c(f"     {text:<12}", "bold")  # noqa: E731
    published = v.published.strftime("%Y-%m-%d") if v.published else "?"
    print(f"{label('Publiée')}{published}   {ui.c('statut NVD : ' + (v.status or '?'), 'gray')}")
    if v.cvss:
        print(f"{label('CVSS')}{ui.severity(v.cvss.severity, v.cvss.score)}  v{v.cvss.version}  "
              f"{ui.c(v.cvss.vector, 'gray')}")
    else:
        print(f"{label('CVSS')}{ui.c('pas encore noté', 'gray')}")
    if v.epss:
        print(f"{label('EPSS')}{ui.epss(v.epss.score)}  "
              f"{ui.c(f'probabilité d’exploitation à 30 jours · percentile {v.epss.percentile * 100:.1f}', 'gray')}")
    source = f"(source : {v.affected_source})" if v.affected_source else ""
    print(f"{label('Produits')}{ui.c(source, 'gray')}")
    if v.affected:
        for a in v.affected[:10]:
            versions = " ; ".join(a.versions[:4]) + (" …" if len(a.versions) > 4 else "")
            print(f"       • {ui.c(f'{a.vendor} / {a.product}', 'bcyan')}" + (f" : {versions}" if versions else ""))
        if len(v.affected) > 10:
            print(ui.c(f"       … {len(v.affected) - 10} autres produits", "gray"))
    else:
        print(ui.c("       non renseigné", "gray"))
    print(label("Description"))
    print(_wrap(v.description or "(aucune)", 7))


def print_exploitation(v: Vulnerability) -> None:
    _title("2", SECTIONS["exploit"], "bred")
    if v.cvss and (explanation := cvss.explain(v.cvss.vector)):
        print_cvss_explanation(explanation, indent=5)
    else:
        print(ui.c("     Vecteur CVSS non disponible.", "gray"))
    print()
    if v.kev:
        due = f", échéance CISA {v.kev.due_date}" if v.kev.due_date else ""
        print(f"     Exploitée activement (KEV) : {ui.yes_no(True)} {ui.c(f'ajoutée le {v.kev.date_added}{due}', 'gray')}")
        print(f"     Utilisée par ransomware    : {ui.yes_no(v.kev.ransomware)}")
    else:
        print(f"     Exploitée activement (KEV) : {ui.yes_no(False)}")
    print(f"     Exploit public référencé   : {ui.yes_no(v.has_exploit_reference)}")
    if v.cwes:
        print()
        for info in v.cwes:
            print_cwe_summary(info, indent=5)
    else:
        print(f"     Faiblesse (CWE)            : {', '.join(v.cwe_ids) or ui.c('non renseignée', 'gray')}")


def print_correction(v: Vulnerability) -> None:
    _title("3", SECTIONS["patch"], "bgreen")
    if v.has_fix:
        print(f"     {ui.c('✔ Correctif disponible', 'bold', 'bgreen')}")
    else:
        print(f"     {ui.c('✖ Aucun correctif publié', 'bold', 'bred')} {ui.c('(selon les sources consultées)', 'gray')}")
    patches = list(dict.fromkeys(r.url for r in v.references if r.has_tag("Patch")))
    _print_refs("Patchs", patches)
    if v.fixed_versions:
        print(f"     {ui.c('Versions corrigées (éditeur)', 'bold')}")
        for fixed in v.fixed_versions[:MAX_REFS]:
            print(f"       → {ui.c(fixed, 'bgreen')}")
    if v.osv_fixes:
        print(f"     {ui.c('Paquets corrigés (OSV)', 'bold')}")
        for fix in v.osv_fixes[:MAX_REFS]:
            fixed = ui.c(", ".join(fix.fixed), "bgreen") if fix.fixed else ui.c("aucune version corrigée", "yellow")
            print(f"       → [{fix.ecosystem}] {ui.c(fix.package, 'bcyan')} : {fixed}")
        if len(v.osv_fixes) > MAX_REFS:
            print(ui.c(f"       … {len(v.osv_fixes) - MAX_REFS} autres paquets", "gray"))
    _print_refs("Bulletins éditeur",
                [r.url for r in v.references if r.has_tag("Vendor Advisory") and r.url not in patches])
    _print_refs("Contournements", [r.url for r in v.references if r.has_tag("Mitigation") and r.url not in patches])
    if v.kev and v.kev.required_action:
        print(f"     {ui.c('Action requise (CISA)', 'bold')}")
        print(_wrap(v.kev.required_action, 7))
    for bulletin in v.certfr:
        if bulletin.solution:
            print(f"     {ui.c(f'Solution CERT-FR ({bulletin.reference})', 'bold', 'bblue')}")
            parts = solution_paragraphs(bulletin.solution)
            for paragraph in parts[:SOLUTION_PREVIEW]:
                print(_wrap(paragraph, 7))
            if len(parts) > SOLUTION_PREVIEW:
                print(ui.c(f"       … {len(parts) - SOLUTION_PREVIEW} paragraphes de plus : section [5] Avis CERT-FR",
                           "gray"))


def print_prevention(v: Vulnerability) -> None:
    _title("4", SECTIONS["prevention"], "byellow")
    if not v.cwes:
        print(ui.c("     Aucune faiblesse CWE associée.", "gray"))
        return
    for info in v.cwes:
        print(f"     {ui.c(info.cwe_id, 'bold', 'byellow')} · {info.name}")
        mitigations = cwe_fr.top_mitigations(info, 3)
        if mitigations:
            print_mitigations(mitigations, indent=7, max_chars=320)
        else:
            print(ui.c("       pas de mesure documentée dans le catalogue", "gray"))
    print(ui.c("     Catalogue MITRE (en anglais) · détail complet : veille cwe <id>", "gray"))


def print_certfr_section(v: Vulnerability) -> None:
    _title("5", SECTIONS["certfr"], "bblue")
    if not v.certfr:
        print(ui.c("     Aucun avis CERT-FR récent ne mentionne cette CVE.", "gray"))
        return
    for b in v.certfr:
        print_bulletin(b, indent=5)


def print_bulletin(b: CertFrBulletin, indent: int = 2) -> None:
    pad = " " * indent
    kind = ui.tag("ALERTE", "bred") if b.kind == "alerte" else ui.tag("AVIS", "bblue")
    day = b.date.strftime("%Y-%m-%d") if b.date else "?"
    print(f"{pad}{kind} {ui.c(b.reference, 'bold')}  {ui.c(day, 'gray')}  {ui.c(b.url, 'gray')}")
    print(_wrap(b.title, indent + 2))
    if b.risks:
        print(f"{pad}  {ui.c('Risques', 'bcyan')} : {', '.join(b.risks)}")
    for system in b.affected_systems[:8]:
        print(f"{pad}  • {system}")
    if b.cves:
        shown = ", ".join(b.cves[:8]) + (f" (+{len(b.cves) - 8})" if len(b.cves) > 8 else "")
        print(f"{pad}  {ui.c('CVE', 'bcyan')} : {shown}")
    if b.solution:
        text = "\n".join(l for l in b.solution.splitlines() if not l.startswith("#"))
        print(f"{pad}  {ui.c('Solution', 'bold')}")
        print(_wrap_paragraphs(markdown_to_text(text), indent + 4))
    for title, url in b.vendor_advisories[:4]:
        print(f"{pad}  → {title} {ui.c(url, 'gray')}")


SECTION_PRINTERS = {
    "resume": print_general,
    "exploit": print_exploitation,
    "patch": print_correction,
    "prevention": print_prevention,
    "certfr": print_certfr_section,
}


def print_detail(v: Vulnerability, sections: Iterable[str] | None = None) -> None:
    print_card(v)
    for name in sections or SECTION_PRINTERS:
        SECTION_PRINTERS[name](v)


# --- CVSS et CWE ------------------------------------------------------------------------


def print_cvss_explanation(explanation: cvss.CvssExplanation, indent: int = 2) -> None:
    pad = " " * indent
    print(f"{pad}{ui.c('En bref', 'bold')} {ui.c(f'(CVSS {explanation.version})', 'gray')}")
    print(_wrap(explanation.summary, indent + 2))
    if explanation.warning:
        print(ui.c(_wrap("⚠ " + explanation.warning, indent + 2), "bold", "bred"))
    width = max(len(aspect) for aspect, _ in explanation.details) if explanation.details else 0
    for aspect, text in explanation.details:
        lines = textwrap.wrap(text, width=max(30, ui.width() - indent - width - 6))
        print(f"{pad}  {ui.c(aspect.ljust(width), 'bcyan')} : {lines[0] if lines else ''}")
        for line in lines[1:]:
            print(f"{pad}  {' ' * width}   {line}")


def print_cwe_summary(info: CweInfo, indent: int = 5) -> None:
    pad = " " * indent
    kind = " (catégorie)" if info.kind == "category" else ""
    print(f"{pad}{ui.c(info.cwe_id, 'bold', 'byellow')} · {info.name}{ui.c(kind, 'gray')}")
    if info.description:
        first = info.description.split("\n\n")[0]
        print(ui.c(_wrap(_shorten(first, 400), indent + 2), "gray"))
    for line in cwe_fr.consequences_fr(info, 3):
        wrapped = textwrap.wrap(line, width=max(30, ui.width() - indent - 18))
        print(f"{pad}  {ui.c('Conséquence', 'bcyan')} : {wrapped[0]}")
        for rest in wrapped[1:]:
            print(f"{pad}                {rest}")
    if info.likelihood:
        label = ui.c("Probabilité d'exploitation", "bcyan")
        print(f"{pad}  {label} : {cwe_fr.likelihood_fr(info)}")


def print_mitigations(mitigations: Iterable[CweMitigation], indent: int, max_chars: int | None = None) -> None:
    pad = " " * indent
    for m in mitigations:
        print(f"{pad}→ {ui.c(cwe_fr.mitigation_label(m) or 'Mesure', 'bold')}")
        text = m.description if max_chars is None else _shorten(m.description, max_chars)
        print(_wrap_paragraphs(text, indent + 2))


def print_cwe(info: CweInfo) -> None:
    ui.section(f"{info.cwe_id} · {info.name}")
    status = f"{info.kind} · statut {info.status or '?'}"
    print(ui.c(f"  {status} · {info.url}", "gray"))
    if info.description:
        print()
        print(_wrap_paragraphs(info.description, 2))
    consequences = cwe_fr.consequences_fr(info, limit=20)
    if consequences or info.likelihood:
        print(f"\n  {ui.c('▸ CONSÉQUENCES', 'bold', 'bred')}")
        for line in consequences:
            print(f"     • {line}")
        if info.likelihood:
            print(f"     Probabilité d'exploitation : {ui.c(cwe_fr.likelihood_fr(info), 'bold')}")
    if info.mitigations:
        print(f"\n  {ui.c(f'▸ PRÉVENTION ({len(info.mitigations)} mesures)', 'bold', 'bgreen')}")
        print_mitigations(cwe_fr.top_mitigations(info, limit=len(info.mitigations)), indent=5)
    print(ui.c("\n  Contenu du catalogue MITRE (en anglais) ; libellés traduits.", "gray"))


def _print_refs(title: str, urls: list[str]) -> None:
    urls = list(dict.fromkeys(urls))
    if not urls:
        return
    print(f"     {ui.c(title, 'bold')}")
    for url in urls[:MAX_REFS]:
        print(f"       → {url}")
    if len(urls) > MAX_REFS:
        print(ui.c(f"       … {len(urls) - MAX_REFS} autres", "gray"))


# --- kev / certfr / epss ---------------------------------------------------------------


def _index(number: int | None) -> str:
    if number is None:
        return ""
    return f"{ui.c('[', 'gray')}{ui.c(f'{number:>2}', 'bold', 'bgreen')}{ui.c(']', 'gray')} "


def print_kev(entries: list[KevEntry], scores: dict[str, EpssScore], numbered: bool = False) -> None:
    ui.section(f"CISA KEV · {len(entries)} AJOUTS")
    if not entries:
        print(ui.c("  Aucun ajout sur la période.", "gray"))
        return
    pad = "     " if numbered else ""
    print(ui.c(f"  {pad}{'AJOUT':<10}  {'CVE':<17} {'EPSS':>6}  RW  {'ÉCHÉANCE':<10}  PRODUIT", "bold", "gray"))
    for number, e in enumerate(entries, 1):
        score = scores.get(e.cve_id)
        rw = ui.c("RW", "bold", "bmagenta") if e.ransomware else ui.c("··", "gray")
        print(
            f"  {_index(number if numbered else None)}{ui.c(e.date_added, 'gray')}  "
            f"{ui.c(_pad(e.cve_id, 17), 'bold', 'bred')} {ui.epss(score.score if score else None)}  {rw}  "
            f"{str(e.due_date or ''):<10}  {ui.c(_pad(f'{e.vendor} / {e.product}', 34), 'bcyan')}"
        )
        print(ui.c(f"  {pad}     └ {_pad(e.name, ui.width() - 12 - len(pad))}", "gray"))


def print_certfr(bulletins: list[CertFrBulletin], numbered: bool = False) -> None:
    ui.section(f"CERT-FR · {len(bulletins)} BULLETINS")
    if not bulletins:
        print(ui.c("  Aucun bulletin sur la période.", "gray"))
        return
    pad = "     " if numbered else ""
    for number, b in enumerate(bulletins, 1):
        kind = ui.tag("ALERTE", "bred") if b.kind == "alerte" else ui.tag(" AVIS ", "bblue")
        day = b.date.strftime("%Y-%m-%d") if b.date else "?"
        cves = ui.c(f"{len(b.cves)} CVE", "gray")
        print(f"  {_index(number if numbered else None)}{ui.c(day, 'gray')}  {kind} {ui.c(b.reference, 'bold')}  {cves}")
        print(f"  {pad}     {_pad(b.title, ui.width() - 10 - len(pad))}")
        if not numbered:
            print(ui.c(f"       {b.url}", "gray"))


def print_epss(ids: list[str], scores: dict[str, EpssScore]) -> None:
    ui.section("EPSS")
    print(ui.c(f"  {'CVE':<17} {'EPSS':>6}  {'PERCENTILE':>10}  DATE", "bold", "gray"))
    for cve in ids:
        s = scores.get(cve)
        if s:
            print(f"  {ui.c(_pad(cve, 17), 'bold')} {ui.epss(s.score)}  {s.percentile * 100:>9.1f}%  {s.date or ''}")
        else:
            print(f"  {ui.c(_pad(cve, 17), 'bold')} {ui.c('   n/a  (pas de score EPSS)', 'gray')}")
