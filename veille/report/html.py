"""Rendu HTML du rapport : page autonome (CSS et JS intégrés, aucune ressource externe).

Tout contenu provenant des sources (descriptions, titres, URL) est échappé :
une description NVD ou un avis ne peut pas injecter de HTML ni de script.
"""

from __future__ import annotations

import re
from html import escape

from .builder import SEVERITY_FR, ReportData, VulnView


def e(text: object) -> str:
    return escape(str(text), quote=True)


def a(url: str, label: str | None = None) -> str:
    """Lien seulement pour http(s) : pas de javascript:, data:…"""
    if not re.match(r"https?://", url):
        return e(label or url)
    return f'<a href="{e(url)}" target="_blank" rel="noopener noreferrer">{e(label or url)}</a>'


_CSS = """
:root{--bg:#0b0f14;--panel:#121821;--panel2:#18202b;--text:#d6dee8;--muted:#8592a3;--border:#253041;
--accent:#3ddc97;--link:#6cb6ff;--crit:#c13cff;--high:#ff4d4f;--med:#ffa940;--low:#52c41a;--none:#8592a3;--kev:#ff4d4f;--warn:#ffcc00}
@media (prefers-color-scheme:light){:root{--bg:#f5f7fa;--panel:#fff;--panel2:#eef1f5;--text:#1d2633;--muted:#5d6b7e;
--border:#d5dbe3;--accent:#0a8f5a;--link:#0b62c4;--warn:#9a6b00}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1150px;margin:0 auto;padding:24px 16px 64px}
code,.mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace;font-size:.92em}
a{color:var(--link);word-break:break-all}
h1{font-size:1.6rem;margin:0}
h2{font-size:1.15rem;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border);color:var(--accent);
font-family:ui-monospace,Consolas,monospace;text-transform:uppercase;letter-spacing:.04em}
h4{margin:18px 0 6px;font-size:.95rem;color:var(--accent)}
header{display:flex;flex-wrap:wrap;gap:8px 24px;align-items:baseline;justify-content:space-between}
.sub{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px}
.card b{display:block;font-size:1.8rem;line-height:1.1}
.card span{color:var(--muted);font-size:.85rem}
.card.red b{color:var(--high)}.card.purple b{color:var(--crit)}.card.orange b{color:var(--med)}
ul.plain{list-style:none;padding:0;margin:0}
ul.plain li{padding:3px 0}
.ok{color:var(--low)}.ko{color:var(--high)}.warn{color:var(--warn)}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{padding:7px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
th{background:var(--panel2);position:sticky;top:0;font-weight:600}
tr:hover td{background:var(--panel)}
td.num{text-align:right;white-space:nowrap}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.8rem;font-weight:700;white-space:nowrap}
.sev-CRITICAL{background:var(--crit);color:#fff}.sev-HIGH{background:var(--high);color:#fff}
.sev-MEDIUM{background:var(--med);color:#1d1d1d}.sev-LOW{background:var(--low);color:#fff}
.sev-NONE,.sev-{background:var(--panel2);color:var(--muted)}
.tag{display:inline-block;padding:0 6px;border-radius:4px;font-size:.75rem;font-weight:700;margin-right:4px;border:1px solid}
.tag.kev{color:var(--kev);border-color:var(--kev)}.tag.rw{color:var(--crit);border-color:var(--crit)}
.tag.exp{color:var(--med);border-color:var(--med)}.tag.fr{color:var(--link);border-color:var(--link)}
.tag.fix{color:var(--low);border-color:var(--low)}.tag.nofix{color:var(--high);border-color:var(--high)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}
.toolbar input{flex:1;min-width:200px;padding:8px 12px;border-radius:8px;border:1px solid var(--border);background:var(--panel);color:var(--text)}
.toolbar button{padding:8px 12px;border-radius:8px;border:1px solid var(--border);background:var(--panel2);color:var(--text);cursor:pointer}
details.vuln{background:var(--panel);border:1px solid var(--border);border-radius:10px;margin:10px 0}
details.vuln.exploited{border-left:4px solid var(--kev)}
details.vuln>summary{cursor:pointer;padding:12px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;list-style:none}
details.vuln>summary::-webkit-details-marker{display:none}
details.vuln>summary .id{font-family:ui-monospace,Consolas,monospace;font-weight:700}
details.vuln>summary .prod{color:var(--muted);flex:1;min-width:160px}
.body{padding:0 18px 16px;border-top:1px solid var(--border)}
.kv{display:grid;grid-template-columns:200px 1fr;gap:4px 14px}
.kv dt{color:var(--muted)}.kv dd{margin:0}
@media (max-width:640px){.kv{grid-template-columns:1fr}.kv dt{margin-top:6px}}
.brief{background:var(--panel2);border-left:3px solid var(--accent);padding:10px 12px;border-radius:6px}
.alert{background:color-mix(in srgb,var(--high) 14%,transparent);border-left:3px solid var(--high);padding:8px 12px;border-radius:6px;margin:8px 0;font-weight:600}
.nofix{color:var(--high);font-weight:700}
.solution{background:var(--panel2);padding:8px 12px;border-radius:6px;margin:6px 0}
.solution p{margin:4px 0}
.muted{color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:.85rem}
"""

_JS = """
const q=document.getElementById('q');
q&&q.addEventListener('input',()=>{const t=q.value.toLowerCase();
document.querySelectorAll('#index tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(t)?'':'none'});
document.querySelectorAll('details.vuln').forEach(d=>{d.style.display=d.textContent.toLowerCase().includes(t)?'':'none'})});
function toggleAll(open){document.querySelectorAll('details.vuln').forEach(d=>d.open=open)}
function openHash(){const t=document.getElementById(decodeURIComponent(location.hash.slice(1)));
if(t&&t.tagName==='DETAILS'){t.open=true;t.scrollIntoView()}}
window.addEventListener('hashchange',openHash);openHash();
"""


def render(data: ReportData) -> str:
    parts: list[str] = []
    w = parts.append
    title = f"Veille vulnérabilités — {data.generated_at:%d/%m/%Y %H:%M} UTC"
    w("<!doctype html><html lang='fr'><head><meta charset='utf-8'>")
    w("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    w(f"<title>{e(title)}</title><style>{_CSS}</style></head><body><main>")
    w(f"<header><h1>🛡️ {e(title)}</h1><div class='sub mono'>veille-vulns · by <b class='ok'>lisox</b></div><div class='sub mono'>période : {data.window_start:%d/%m/%Y %H:%M} → "
      f"{data.window_end:%d/%m/%Y %H:%M} UTC</div></header>")

    w("<div class='cards'>")
    for value, label, cls in (
        (len(data.all), "failles retenues", ""),
        (data.critical, "critiques (CVSS ≥ 9)", "purple"),
        (data.exploited, "exploitées activement", "red"),
        (data.ransomware, "liées à des ransomwares", "purple"),
        (data.without_fix, "sans correctif publié", "orange"),
    ):
        w(f"<div class='card {cls}'><b>{value}</b><span>{e(label)}</span></div>")
    w("</div>")
    w(f"<p class='sub'>{data.total_fetched} CVE récupérées · {data.new_count} nouvelles depuis le dernier "
      f"lancement · {data.excluded_count} écartées par les filtres · {len(data.unscored)} sans score CVSS</p>")

    w("<h2>Sources</h2><ul class='plain'>")
    for s in data.statuses:
        if not s.ok:
            w(f"<li><span class='ko'>✖</span> <b>{e(s.name)}</b> — indisponible : {e(s.message)}</li>")
        elif s.message:
            w(f"<li><span class='warn'>⚠</span> <b>{e(s.name)}</b> — {s.count} entrées — {e(s.message)}</li>")
        else:
            w(f"<li><span class='ok'>✔</span> <b>{e(s.name)}</b> <span class='muted'>— {s.count} entrées "
              f"({s.duration:.1f} s)</span></li>")
    w("</ul>")

    w("<h2>Filtres appliqués</h2><ul class='plain'>")
    for line in data.filters or ["aucun"]:
        w(f"<li>› {e(line)}</li>")
    for reason, count in data.excluded.items():
        w(f"<li class='muted'>écartées ({e(reason)}) : {count}</li>")
    w("</ul>")

    if not data.all:
        w("<p><i>Aucune nouvelle faille ne correspond aux critères.</i></p>")
    else:
        w("<h2>Index</h2><div class='toolbar'><input id='q' placeholder='Filtrer (CVE, produit, éditeur…)'>"
          "<button onclick='toggleAll(true)'>Tout déplier</button><button onclick='toggleAll(false)'>Tout replier</button></div>")
        w("<div class='table-wrap'><table id='index'><thead><tr><th>#</th><th>CVE</th><th>CVSS</th><th>EPSS</th>"
          "<th>Indicateurs</th><th>Produit</th></tr></thead><tbody>")
        for v in data.all:
            epss = f"{v.epss * 100:.1f} %" if v.epss is not None else "n/a"
            w(f"<tr><td class='num'>{v.rank}</td><td class='mono'><a href='#{e(v.anchor)}'>{e(v.cve_id)}</a></td>"
              f"<td>{_severity_badge(v)}</td><td class='num'>{epss}</td><td>{_tags(v)}</td>"
              f"<td>{e(v.short_product)}</td></tr>")
        w("</tbody></table></div>")
        w("<p class='sub'>Ordre : exploitées (CISA KEV) d'abord, puis EPSS, puis CVSS.</p>")
        w("<h2>Détail</h2>")
        for v in data.vulns:
            w(_vuln(v))
        if data.unscored:
            w("<h2>Failles sans score CVSS</h2><p class='sub'>Pas encore notées par NVD ni par le CNA, "
              "ou NVD indisponible lors du lancement.</p>")
            for v in data.unscored:
                w(_vuln(v))
        if data.appendix:
            w(_appendix(data))

    w("<footer>Généré par <b>veille-vulns</b> · coded by <b class='ok'>lisox</b> — à partir de sources publiques : NVD, CISA KEV, FIRST EPSS, CERT-FR, "
      "CVE.org, OSV, CWE MITRE. Le contenu CWE est en anglais.</footer>")
    w(f"</main><script>{_JS}</script></body></html>")
    return "\n".join(parts)


def _severity_badge(v: VulnView) -> str:
    if not v.severity:
        return "<span class='badge sev-'>non noté</span>"
    return f"<span class='badge sev-{e(v.severity)}'>{e(v.cvss_label.split(' · CVSS')[0])}</span>"


def _tags(v: VulnView) -> str:
    tags = []
    if v.exploited:
        tags.append("<span class='tag kev'>KEV</span>")
    if v.ransomware:
        tags.append("<span class='tag rw'>RANSOMWARE</span>")
    if v.exploit_reference:
        tags.append("<span class='tag exp'>EXPLOIT</span>")
    if v.certfr:
        tags.append("<span class='tag fr'>CERT-FR</span>")
    tags.append("<span class='tag fix'>CORRECTIF</span>" if v.has_fix else "<span class='tag nofix'>SANS CORRECTIF</span>")
    return "".join(tags)


def _yes(value: bool, unknown: bool = False) -> str:
    if value:
        return "<b class='ko'>OUI</b>"
    return "<span class='muted'>non connu</span>" if unknown else "non"


def _vuln(v: VulnView) -> str:
    h: list[str] = []
    w = h.append
    classes = "vuln exploited" if v.exploited else "vuln"
    w(f"<details class='{classes}' id='{e(v.anchor)}'{' open' if v.exploited else ''}>")
    w(f"<summary><span class='muted mono'>#{v.rank}</span><span class='id'>{e(v.cve_id)}</span>"
      f"{_severity_badge(v)}{_tags(v)}<span class='prod'>{e(v.short_product)}</span></summary><div class='body'>")

    # 1. Informations générales
    w("<h4>1. Informations générales</h4><dl class='kv'>")
    w(f"<dt>Publication</dt><dd>{e(v.published)} <span class='muted'>({e(v.nvd_status or 'statut NVD inconnu')})</span></dd>")
    vector = f" <code>{e(v.cvss_vector)}</code>" if v.cvss_vector else ""
    w(f"<dt>CVSS</dt><dd>{e(v.cvss_label)}{vector}</dd>")
    w(f"<dt>EPSS</dt><dd>{e(v.epss_label)}</dd>")
    source = f" <span class='muted'>(source : {e(v.products_source)})</span>" if v.products_source else ""
    if v.products:
        items = "".join(f"<li>{e(p)}</li>" for p in v.products[:15])
        more = f"<li class='muted'>… et {len(v.products) - 15} autres</li>" if len(v.products) > 15 else ""
        w(f"<dt>Produits touchés</dt><dd>{source}<ul>{items}{more}</ul></dd>")
    else:
        w("<dt>Produits touchés</dt><dd class='muted'>non renseigné</dd>")
    w(f"<dt>Description</dt><dd>{e(v.description or 'aucune')}</dd></dl>")

    # 2. Mode d'exploitation
    w("<h4>2. Mode d'exploitation</h4>")
    if v.explanation:
        w(f"<div class='brief'>{e(v.explanation.summary)}</div>")
        if v.explanation.warning:
            w(f"<div class='alert'>⚠ {e(v.explanation.warning)}</div>")
        w("<dl class='kv'>")
        for aspect, text in v.explanation.details:
            w(f"<dt>{e(aspect)}</dt><dd>{e(text)}</dd>")
        w("</dl>")
    w("<dl class='kv'>")
    w(f"<dt>Exploitée activement</dt><dd>{_yes(v.exploited)}"
      + (f" <span class='muted'>— {e(v.kev_label)}</span>" if v.kev_label else "") + "</dd>")
    w(f"<dt>Ransomware</dt><dd>{_yes(v.ransomware, unknown=not v.exploited)}</dd>")
    w(f"<dt>Exploit public référencé</dt><dd>{_yes(v.exploit_reference)}</dd>")
    for c in v.cwes:
        body = a(c.url, c.cwe_id) + (f" — {e(c.name)}" if c.name else "")
        if c.summary:
            body += f"<div class='muted'>{e(c.summary)}</div>"
        if c.consequences:
            body += "<ul>" + "".join(f"<li>{e(x)}</li>" for x in c.consequences) + "</ul>"
        if c.likelihood:
            body += f"<div>Probabilité d'exploitation : <b>{e(c.likelihood)}</b></div>"
        w(f"<dt>Faiblesse (CWE)</dt><dd>{body}</dd>")
    w("</dl>")

    # 3. Correction
    w("<h4>3. Correction</h4>")
    if not v.has_fix:
        w("<p class='nofix'>✖ Aucun correctif publié <span class='muted'>(selon les sources consultées)</span></p>")
    w("<dl class='kv'>")
    for title, urls in (("Correctifs (patchs)", v.patches), ("Bulletins éditeur", v.advisories),
                        ("Contournements", v.mitigations)):
        if urls:
            items = "".join(f"<li>{a(u)}</li>" for u in urls[:10])
            more = f"<li class='muted'>… et {len(urls) - 10} autres</li>" if len(urls) > 10 else ""
            w(f"<dt>{title}</dt><dd><ul>{items}{more}</ul></dd>")
    if v.cna_fixes:
        w("<dt>Versions corrigées (éditeur)</dt><dd><ul>" + "".join(f"<li>{e(x)}</li>" for x in v.cna_fixes[:15]) + "</ul></dd>")
    if v.osv_fixes:
        w("<dt>Paquets corrigés (OSV)</dt><dd><ul>" + "".join(f"<li class='mono'>{e(x)}</li>" for x in v.osv_fixes[:15]) + "</ul></dd>")
    if v.kev_action:
        w(f"<dt>Action requise (CISA)</dt><dd>{e(v.kev_action)}</dd>")
    for b in v.certfr:
        body = f"{a(b.url, b.reference)} <span class='muted'>({e(b.kind)}, {e(b.date)})</span><div>{e(b.title)}</div>"
        if b.affected_systems:
            body += "<ul>" + "".join(f"<li>{e(s)}</li>" for s in b.affected_systems[:8]) + "</ul>"
        if b.solution:
            body += "<div class='solution'>" + "".join(f"<p>{e(p)}</p>" for p in b.solution) + "</div>"
        if b.vendor_advisories:
            body += "<ul>" + "".join(f"<li>{a(url, t)}</li>" for t, url in b.vendor_advisories[:5]) + "</ul>"
        w(f"<dt>CERT-FR</dt><dd>{body}</dd>")
    for c in v.cwes:
        if c.prevention:
            labels = " ; ".join(e(label) for label, _ in c.prevention)
            w(f"<dt>Prévention ({e(c.cwe_id)})</dt><dd>{labels} — "
              f"<a href='#{e(c.cwe_id.lower())}'>détail dans l'annexe</a></dd>")
    w("</dl></div></details>")
    return "\n".join(h)


def _appendix(data: ReportData) -> str:
    h = ["<h2>Annexe — faiblesses (CWE) rencontrées</h2>",
         "<p class='sub'>Catalogue CWE du MITRE (contenu en anglais, libellés traduits). "
         "Mesures les plus efficaces d'abord.</p>"]
    for c, count in data.appendix:
        h.append(f"<details class='vuln' id='{e(c.cwe_id.lower())}'><summary><span class='id'>{e(c.cwe_id)}</span>"
                 f"<span class='prod'>{e(c.name)}</span><span class='muted'>{count} faille{'s' if count > 1 else ''}"
                 f"</span></summary><div class='body'>")
        if c.summary:
            h.append(f"<p>{e(c.summary)}</p>")
        h.append("<dl class='kv'>")
        if c.consequences:
            h.append("<dt>Conséquences</dt><dd><ul>" + "".join(f"<li>{e(x)}</li>" for x in c.consequences) + "</ul></dd>")
        if c.likelihood:
            h.append(f"<dt>Probabilité d'exploitation</dt><dd><b>{e(c.likelihood)}</b></dd>")
        h.append(f"<dt>Référence</dt><dd>{a(c.url)}</dd>")
        if c.prevention:
            items = "".join(f"<li><b>{e(label)}</b><div>{e(text)}</div></li>" for label, text in c.prevention)
            h.append(f"<dt>Prévention</dt><dd><ul>{items}</ul></dd>")
        h.append("</dl></div></details>")
    return "\n".join(h)


__all__ = ["render", "SEVERITY_FR"]
