"""Rendu Markdown du rapport."""

from __future__ import annotations

import re

from .builder import SEVERITY_FR, ReportData, VulnView

_SEVERITY_ICON = {"CRITICAL": "🟣", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢", "NONE": "⚪"}


def esc(text: str) -> str:
    """Neutralise le HTML et les caractères qui cassent un tableau Markdown."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_|\[\]])", r"\\\1", " ".join(text.split()))


def link(url: str, label: str | None = None) -> str:
    if not re.match(r"https?://", url):
        return esc(label or url)
    safe = url.replace(" ", "%20").replace(")", "%29").replace("<", "%3C").replace(">", "%3E")
    return f"[{esc(label or url)}]({safe})"


def render(data: ReportData) -> str:
    out: list[str] = []
    w = out.append
    w(f"# Rapport de veille vulnérabilités — {data.generated_at:%d/%m/%Y %H:%M} UTC")
    w("")
    w(f"Période analysée : du **{data.window_start:%d/%m/%Y %H:%M}** au **{data.window_end:%d/%m/%Y %H:%M}** (UTC).")
    w("")

    w("## Résumé")
    w("")
    w("| Indicateur | Nombre |")
    w("|---|---:|")
    w(f"| Failles retenues | **{len(data.all)}** |")
    w(f"| dont critiques (CVSS ≥ 9) | **{data.critical}** |")
    w(f"| dont exploitées activement (CISA KEV) | **{data.exploited}** |")
    w(f"| dont utilisées par des ransomwares | **{data.ransomware}** |")
    w(f"| dont sans correctif publié | **{data.without_fix}** |")
    w(f"| dont sans score CVSS | {len(data.unscored)} |")
    w("")
    w(f"{data.total_fetched} CVE récupérées, {data.new_count} nouvelles depuis le dernier lancement, "
      f"{data.excluded_count} écartées par les filtres.")
    if data.excluded:
        w("")
        for reason, count in data.excluded.items():
            w(f"- écartées ({esc(reason)}) : {count}")
    w("")

    w("## Sources")
    w("")
    for s in data.statuses:
        if not s.ok:
            w(f"- ❌ **{esc(s.name)}** — indisponible : {esc(s.message)}")
        elif s.message:
            w(f"- ⚠️ **{esc(s.name)}** — {s.count} entrées — {esc(s.message)}")
        else:
            w(f"- ✅ **{esc(s.name)}** — {s.count} entrées ({s.duration:.1f} s)")
    w("")

    w("## Filtres appliqués")
    w("")
    for line in data.filters or ["aucun"]:
        w(f"- {esc(line)}")
    w("")

    if not data.all:
        w("_Aucune nouvelle faille ne correspond aux critères._")
        return "\n".join(out) + "\n"

    w("## Index (par priorité : exploitées, puis EPSS, puis CVSS)")
    w("")
    w("| # | CVE | CVSS | EPSS | Exploitée | Correctif | Produit |")
    w("|---:|---|---|---:|---|---|---|")
    for v in data.all:
        sev = f"{_SEVERITY_ICON.get(v.severity, '')} {v.cvss_label.split(' · CVSS')[0]}" if v.severity else "non noté"
        exploited = "🔥 KEV" + (" · ransomware" if v.ransomware else "") if v.exploited else "—"
        epss = f"{v.epss * 100:.1f} %" if v.epss is not None else "n/a"
        w(f"| {v.rank} | [{v.cve_id}](#{v.anchor}) | {sev} | {epss} | {exploited} | "
          f"{'✅' if v.has_fix else '❌ aucun'} | {esc(v.short_product)} |")
    w("")

    w("## Détail")
    w("")
    for v in data.vulns:
        _render_vuln(v, w)
    if data.unscored:
        w("## Failles sans score CVSS")
        w("")
        w("_Pas encore notées par NVD ni par le CNA, ou NVD indisponible lors du lancement._")
        w("")
        for v in data.unscored:
            _render_vuln(v, w)
    if data.appendix:
        _render_appendix(data, w)
    w("---")
    w("_Généré par veille-vulns (coded by **lisox**) à partir de sources publiques : NVD, CISA KEV, FIRST EPSS, CERT-FR, "
      "CVE.org, OSV, CWE MITRE._")
    return "\n".join(out) + "\n"


def _render_vuln(v: VulnView, w) -> None:
    sev = SEVERITY_FR.get(v.severity, "non notée") if v.severity else "non notée"
    flags = " 🔥 exploitée" if v.exploited else ""
    w(f'<a id="{v.anchor}"></a>')
    w("")
    w(f"### {v.rank}. {v.cve_id} — {_SEVERITY_ICON.get(v.severity, '')} {sev}{flags}")
    w("")

    w("#### 1. Informations générales")
    w("")
    w(f"- **Publication** : {v.published} ({esc(v.nvd_status or 'statut NVD inconnu')})")
    w(f"- **CVSS** : {esc(v.cvss_label)}" + (f" — `{v.cvss_vector}`" if v.cvss_vector else ""))
    w(f"- **EPSS** : {esc(v.epss_label)}")
    source = f" _(source : {esc(v.products_source)})_" if v.products_source else ""
    if v.products:
        w(f"- **Produits et versions touchés**{source} :")
        for p in v.products[:15]:
            w(f"  - {esc(p)}")
        if len(v.products) > 15:
            w(f"  - … et {len(v.products) - 15} autres")
    else:
        w("- **Produits et versions touchés** : non renseigné")
    w(f"- **Description** : {esc(v.description or 'aucune')}")
    w("")

    w("#### 2. Mode d'exploitation")
    w("")
    if v.explanation:
        w(f"> {esc(v.explanation.summary)}")
        if v.explanation.warning:
            w(">")
            w(f"> ⚠️ **{esc(v.explanation.warning)}**")
        w("")
        for aspect, text in v.explanation.details:
            w(f"- **{esc(aspect)}** : {esc(text)}")
    else:
        w("- Vecteur CVSS non disponible.")
    w(f"- **Exploitée activement (CISA KEV)** : "
      + (f"**OUI** — {esc(v.kev_label)}" if v.exploited else "non"))
    w(f"- **Utilisée par des ransomwares** : {'**OUI**' if v.ransomware else 'non' if v.exploited else 'non connu'}")
    w(f"- **Exploit public référencé par NVD** : {'**OUI**' if v.exploit_reference else 'non'}")
    for c in v.cwes:
        name = f" — {esc(c.name)}" if c.name else ""
        w(f"- **Faiblesse** : {link(c.url, c.cwe_id)}{name}")
        if c.summary:
            w(f"  - {esc(c.summary)}")
        for line in c.consequences:
            w(f"  - Conséquence : {esc(line)}")
        if c.likelihood:
            w(f"  - Probabilité d'exploitation : {esc(c.likelihood)}")
    w("")

    w("#### 3. Correction")
    w("")
    if not v.has_fix:
        w("> ❌ **Aucun correctif publié** (selon les sources consultées).")
        w("")
    _url_list(w, "Correctifs (patchs)", v.patches)
    _url_list(w, "Bulletins éditeur", v.advisories)
    _url_list(w, "Contournements", v.mitigations)
    if v.cna_fixes:
        w("- **Versions corrigées (déclarées par l'éditeur)** :")
        for fix in v.cna_fixes[:15]:
            w(f"  - {esc(fix)}")
    if v.osv_fixes:
        w("- **Versions corrigées des paquets (OSV)** :")
        for fix in v.osv_fixes[:15]:
            w(f"  - {esc(fix)}")
        if len(v.osv_fixes) > 15:
            w(f"  - … et {len(v.osv_fixes) - 15} autres paquets")
    if v.kev_action:
        w(f"- **Action requise par la CISA** : {esc(v.kev_action)}")
    for b in v.certfr:
        w(f"- **CERT-FR** {link(b.url, b.reference)} ({b.kind}, {b.date}) : {esc(b.title)}")
        for system in b.affected_systems[:8]:
            w(f"  - Système affecté : {esc(system)}")
        for paragraph in b.solution:
            w(f"  - {esc(paragraph)}")
        for title, url in b.vendor_advisories[:5]:
            w(f"  - {link(url, title)}")
    for c in v.cwes:
        if c.prevention:
            labels = " ; ".join(esc(label) for label, _ in c.prevention)
            w(f"- **Prévention générale ({c.cwe_id})** : {labels} — "
              f"[détail dans l'annexe](#{c.cwe_id.lower()})")
    w("")
    w("---")
    w("")


def _render_appendix(data: ReportData, w) -> None:
    w("## Annexe — faiblesses (CWE) rencontrées")
    w("")
    w("_Catalogue CWE du MITRE (contenu en anglais, libellés traduits). Mesures les plus efficaces d'abord._")
    w("")
    for c, count in data.appendix:
        w(f'<a id="{c.cwe_id.lower()}"></a>')
        w("")
        w(f"### {c.cwe_id} — {esc(c.name)} ({count} faille{'s' if count > 1 else ''})")
        w("")
        if c.summary:
            w(esc(c.summary))
            w("")
        for line in c.consequences:
            w(f"- Conséquence : {esc(line)}")
        if c.likelihood:
            w(f"- Probabilité d'exploitation : {esc(c.likelihood)}")
        w(f"- Référence : {link(c.url)}")
        if c.prevention:
            w("")
            w("**Prévention :**")
            w("")
            for label, text in c.prevention:
                w(f"- _{esc(label)}_ — {esc(text)}")
        w("")


def _url_list(w, title: str, urls: list[str]) -> None:
    if not urls:
        return
    w(f"- **{title}** :")
    for url in urls[:10]:
        w(f"  - {link(url)}")
    if len(urls) > 10:
        w(f"  - … et {len(urls) - 10} autres")
