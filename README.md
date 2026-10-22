# veille-vulns

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Sources](https://img.shields.io/badge/sources-100%25%20publiques-brightgreen)
![Author](https://img.shields.io/badge/coded%20by-lisox-red)

```
 ██╗   ██╗███████╗██╗██╗     ██╗     ███████╗
 ██║   ██║██╔════╝██║██║     ██║     ██╔════╝
 ██║   ██║█████╗  ██║██║     ██║     █████╗
 ╚██╗ ██╔╝██╔══╝  ██║██║     ██║     ██╔══╝
  ╚████╔╝ ███████╗██║███████╗███████╗███████╗
   ╚═══╝  ╚══════╝╚═╝╚══════╝╚══════╝╚══════╝
  ──────────────[ coded by lisox ]──────────────
```

**Outil de veille sur les vulnérabilités en ligne de commande.** À chaque
lancement, il récupère les nouvelles CVE, indique **si elles sont exploitées**,
**comment elles s'exploitent** et **comment les corriger**, puis génère un
rapport daté en Markdown et en HTML.

Uniquement des sources publiques et gratuites : aucune IA, aucune API payante.

## Fonctionnalités

- 🔎 **Nouvelles CVE** depuis le dernier lancement (NVD), sans doublons grâce à un cache local
- 🔥 **Exploitation active** et usage par des ransomwares (CISA KEV), probabilité d'exploitation (EPSS)
- 🧠 **Vecteur CVSS expliqué en français** : accès réseau/local, privilèges, interaction, impacts
- 🩹 **Correctifs** : patchs, versions corrigées (éditeur et paquets OSV), action CISA, solution CERT-FR, mention claire « Aucun correctif publié »
- 🛡️ **Prévention** : type de faiblesse (CWE MITRE) et mesures de prévention
- 🇫🇷 **Avis et alertes CERT-FR** rapprochés des CVE
- 🎯 **Filtres** : score CVSS minimum, éditeurs/produits surveillés, failles exploitées seulement
- 📊 **Priorisation** : exploitées d'abord, puis EPSS, puis CVSS
- 📄 **Rapport** Markdown + page HTML autonome avec recherche
- 💻 **Menu interactif** façon outil de pentest, ou sous-commandes pour les scripts

## Démarrage rapide

```powershell
git clone https://github.com/Lisox400/veille-vulns.git
cd veille-vulns
pip install -e .
veille            # menu interactif
veille scan       # ou directement : scan + rapport
```

## Installation

Python 3.11 ou plus récent. Seule dépendance : `requests`.

```powershell
git clone https://github.com/Lisox400/veille-vulns.git
cd veille-vulns
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

`pip install -e .` installe la commande **`veille`**. Sans installation,
`python -m veille` fonctionne de la même façon.

### Clé API NVD (recommandée)

Sans clé, NVD limite à 5 requêtes par 30 s : l'outil fonctionne, mais plus
lentement sur les grandes fenêtres. La clé est gratuite :
<https://nvd.nist.gov/developers/request-an-api-key>.

Elle se lit **uniquement** depuis la variable d'environnement `NVD_API_KEY`,
jamais depuis un fichier :

```powershell
$env:NVD_API_KEY = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"     # session courante
setx NVD_API_KEY "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"       # permanent (nouveau terminal)
```

`veille sources` indique si la clé est prise en compte.

## Configuration

```powershell
copy config.example.toml config.toml
```

Sans `config.toml`, les valeurs par défaut s'appliquent. Toutes les options
sont commentées dans `config.example.toml`.

| Section | Option | Rôle |
|---|---|---|
| `[general]` | `data_dir`, `reports_dir` | cache local et dossier des rapports (relatifs au fichier de config) |
| | `first_run_hours` | fenêtre du tout premier lancement (24 h) |
| | `overlap_hours` | recouvrement avec la fenêtre précédente (retards d'indexation NVD) |
| `[filters]` | `min_cvss` | score CVSS minimum |
| | `include_unscored` | garde les CVE sans score CVSS, dans une section à part |
| | `only_exploited` | uniquement les failles du catalogue CISA KEV |
| | `always_keep_exploited` | une faille exploitée n'est jamais écartée par `min_cvss` |
| | `keywords` | éditeurs/produits surveillés (au moins un doit correspondre) |
| | `exclude_keywords` | mots-clés à exclure |
| `[sources]` | `epss`, `certfr`, `osv`, `cveorg`, `cwe` | active ou désactive chaque source complémentaire |
| | `workers` | requêtes parallèles pour OSV / CVE.org / CERT-FR |

Les mots-clés sont insensibles à la casse et cherchés **par mots entiers** dans
la description, les produits (NVD, CVE.org, KEV, OSV), les CPE et les avis
CERT-FR. `"exchange server"` correspond au CPE `microsoft:exchange_server`,
mais `"ssl"` ne correspond pas à « openssl ».

## Utilisation

### Mode menu (le plus simple)

Tape simplement `veille` :

```
  ──────────────[ coded by lisox ]──────────────  v0.3.0

  [1] Nouvelles vulnérabilités         scan depuis le dernier lancement
  [2] Infos sur une vulnérabilité      fiche d'une CVE
  [3] Patchs / correctifs              comment corriger une CVE
  [4] Failles exploitées (KEV)         derniers ajouts CISA
  [5] Alertes CERT-FR                  avis et alertes en français
  [6] Faiblesse CWE                    type de faille et prévention
  [7] Décoder un vecteur CVSS          en clair, en français
  [8] Ouvrir le dernier rapport        page HTML dans le navigateur
  [9] État & diagnostic                cache, sources, clé NVD
  [0] Quitter

veille >
```

Chaque écran affiche peu d'informations à la fois : la liste des failles est
paginée (10 par page) et chaque fiche s'ouvre sur un résumé, avec un sous-menu
pour descendre dans le détail :

```
  [1] Résumé & produits touchés
  [2] Comment elle est exploitée
  [3] Patchs & correctifs
  [4] Prévention (type de faille)
  [5] Avis CERT-FR
  [6] Tout afficher
  [7] Exporter la fiche (rapport MD + HTML)
  [0] Retour
```

`Ctrl+C` ou `0` pour revenir en arrière.

### Mode commandes (scripts, usage rapide)

```
veille <commande> [options]

  menu      menu interactif (comme `veille` seul)

  scan      récupère, enrichit, filtre, priorise et génère le rapport
  cve       fiche détaillée d'une ou plusieurs CVE (exploitation + correction)
  kev       derniers ajouts au catalogue CISA KEV
  certfr    derniers avis et alertes du CERT-FR
  epss      score EPSS d'une ou plusieurs CVE
  cwe       fiche d'une faiblesse CWE (conséquences, prévention) ou recherche
  cvss      explique un vecteur CVSS en français
  sources   teste la disponibilité de chaque source
  status    état du cache local et derniers lancements
  reset     vide le cache local
```

#### Le scan quotidien

```powershell
veille scan                            # depuis le dernier lancement (24 h la 1re fois) + rapport
veille scan --since 7d -n 50           # fenêtre imposée (48h, 7d, 2026-10-01), top 50 à l'écran
veille scan --min-cvss 8 -k fortinet -k ivanti   # filtres ponctuels (surchargent la config)
veille scan --kev-only                 # uniquement les failles exploitées activement
veille scan -x "wordpress plugin"      # exclusion supplémentaire
veille scan --no-filter                # ignore les filtres de la config
veille scan --format html -o C:\rapports
veille scan --no-report --no-enrich    # aperçu rapide NVD + KEV dans le terminal
veille scan --show-seen --dry-run      # rejouer une fenêtre sans toucher au cache
```

Déroulement d'un scan :

1. NVD : CVE publiées dans la fenêtre, plus les CVE (même anciennes) **ajoutées
   au catalogue KEV** pendant cette fenêtre ;
2. CISA KEV : exploitation active, ransomware, action requise, échéance ;
3. retrait des CVE déjà vues (cache SQLite) ;
4. filtres CVSS/KEV, *avant* l'enrichissement, pour économiser des requêtes ;
5. enrichissement : EPSS, CERT-FR, CVE.org (produits quand NVD n'a pas de CPE,
   et toujours pour les failles exploitées), OSV, CWE ;
6. filtres par mots-clés (après l'enrichissement, qui complète les produits) ;
7. priorisation : **exploitées (KEV) d'abord, puis EPSS, puis CVSS** ;
8. résumé dans le terminal + rapport `reports/veille_AAAA-MM-JJ_HHMM.md` / `.html`.

#### Autres commandes

```powershell
veille cve CVE-2024-3400 CVE-2021-44228          # fiche complète dans le terminal
veille cve CVE-2024-3400 -s patch                # seulement les correctifs
veille cve CVE-2024-3400 -s exploit -s prevention   # sections : resume, exploit, patch, prevention, certfr
veille cve CVE-2024-3400 --report                # … et export Markdown/HTML
veille kev --days 30 --ransomware
veille kev -g fortinet
veille certfr --alertes -d 30
veille certfr -g cisco
veille epss CVE-2021-44228
veille cwe 79 CWE-89                             # conséquences + mesures de prévention
veille cwe -g deserialization                    # recherche par nom
veille cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
veille sources
veille status
veille <commande> -h                             # aide d'une commande
```

Options globales (avant ou après la commande) : `-c fichier.toml`, `-v`
(journal détaillé), `-q` (sans bannière), `--no-color` (ou variable `NO_COLOR`).

Colonnes du terminal : `KEV` exploitée activement · `RW` ransomware · `EXP`
exploit public référencé par NVD · `FR` avis CERT-FR · `FIX`/`NOFIX` correctif
attesté ou non.

Codes de sortie : `0` succès, `1` source principale indisponible, `2` erreur de
configuration ou d'argument, `130` interruption (Ctrl+C).

## Le rapport

Un fichier Markdown et une page HTML autonome (aucune ressource externe),
horodatés. La page HTML a un champ de recherche dans l'index ; les failles
exploitées y sont dépliées par défaut.

- **Résumé** : failles retenues, critiques (CVSS ≥ 9), exploitées activement,
  liées à des ransomwares, sans correctif publié, sans score CVSS, et nombre de
  CVE écartées par chaque filtre.
- **Sources** : état de chaque source. Une source en panne est signalée ici,
  et l'outil continue avec les autres.
- **Filtres appliqués**, puis **index** par ordre de priorité.
- **Fiche par faille** :
  1. *Informations générales* : CVE, produits et versions touchés (avec la
     source de l'information), description, CVSS, EPSS, date de publication ;
  2. *Mode d'exploitation* : vecteur CVSS expliqué en français (accès,
     complexité, privilèges, interaction, portée, impacts), CWE avec conséquences,
     exploitation active (KEV), ransomware, exploit public référencé (oui/non,
     aucun code n'est récupéré) ;
  3. *Correction* : correctifs (patchs) en premier, bulletins éditeur,
     contournements, versions corrigées (CNA et paquets OSV), action requise
     par la CISA, section Solution/Contournement de l'avis CERT-FR, mention
     **« Aucun correctif publié »** le cas échéant, et mesures de prévention
     de la CWE.
- **Failles sans score CVSS** (section à part).
- **Annexe CWE** : chaque faiblesse rencontrée, une seule fois, avec ses
  mesures de prévention détaillées (les fiches y renvoient).

Tout le contenu provenant des sources est **échappé** : une description NVD ou
un avis contenant du HTML ou du JavaScript ne peut rien injecter dans le rapport.
Seuls les liens `http(s)` sont cliquables.

## Sources

| Source | Rôle | Cache local |
|---|---|---|
| NVD (API CVE 2.0) | CVE de la fenêtre, CVSS, CWE, références, CPE | non |
| CISA KEV | exploitation active, ransomware, action requise, échéance | `data/kev.json` (ETag) |
| FIRST EPSS | probabilité d'exploitation à 30 jours | non |
| CERT-FR | avis et alertes en français, sections Solution / Contournement | `data/certfr/*.json` |
| CVE.org | produits/versions touchés et corrigés déclarés par le CNA | non |
| OSV | versions corrigées des paquets (PyPI, npm, Maven, Go, distributions…) | non |
| CWE MITRE | nom, description, conséquences, prévention | `data/cwec_latest.xml.zip` (vérifié chaque semaine) |

Résilience : retries avec backoff, respect des limites de débit, reprise des
transferts NVD interrompus. Si une source en ligne est hors service, la dernière
copie locale est utilisée quand elle existe (KEV, CWE). Pour les sources
interrogées CVE par CVE, l'outil abandonne après 5 échecs consécutifs plutôt
que d'enchaîner les timeouts.

## Cache

`data/veille.db` (SQLite) mémorise les CVE déjà vues et la fin de la fenêtre du
dernier lancement **réussi**. Le lancement suivant repart de ce point, avec un
recouvrement de 2 h. Si NVD est indisponible, la fenêtre n'avance pas.

- Une CVE déjà vue **réapparaît une fois** le jour où elle entre au catalogue KEV.
- Les CVE écartées par les filtres sont aussi marquées comme vues. Après un
  changement de filtres, utilise `--show-seen` pour rejouer une fenêtre.
- `veille reset` vide le cache (seuls les fichiers créés par l'outil sont
  supprimés).

## Tests

```powershell
python -m unittest discover -s tests -t .
```

Les tests tournent hors ligne, sur des données d'exemple.

## Structure

```
veille/
├── cli.py            sous-commandes et options
├── interactive.py    menu interactif
├── services.py       opérations partagées par le menu et les commandes
├── pipeline.py       orchestration : sources, fusion, nouveautés, enrichissement, cache
├── filtering.py      filtres et priorisation
├── config.py         lecture et validation du TOML
├── models.py         modèle commun (Vulnerability, KevEntry, CweInfo…)
├── http.py           session HTTP (retry, limiteur de débit, téléchargement mis en cache)
├── cache.py          cache SQLite
├── checks.py         diagnostic des sources
├── ui.py             rendu terminal (couleurs, bannière, progression)
├── sources/          nvd, cisa_kev, epss, certfr, cveorg, osv, cwe
├── enrichment/       cvss.py (vecteur → français), cwe.py (libellés CWE traduits)
└── report/           console.py (terminal), builder.py (modèle), markdown.py, html.py
```

## Limites connues

- Le catalogue CWE est **en anglais**. Sans traduction automatique, seuls les
  libellés à liste fermée sont traduits (phases, stratégies, portées, impacts,
  efficacité). Les descriptions restent en anglais.
- Les CVE récentes ne sont pas encore analysées par NVD (pas de CPE). Les
  produits viennent alors de CVE.org (déclaration du CNA).
- « Version corrigée » côté CVE.org : point de changement déclaré, ou à défaut
  borne haute exclusive de la plage affectée (« affecté avant 1.6.20 »).
- CERT-FR : seuls les 40 derniers avis et les 40 dernières alertes (flux RSS)
  sont rapprochés des CVE.
- « Correctif attesté » = référence NVD marquée *Patch*, version corrigée
  (CNA/OSV) ou section Solution d'un avis CERT-FR. Un bulletin éditeur seul ne
  suffit pas : la mention « Aucun correctif publié » est volontairement prudente.
- Sans filtre, un rapport de 24 h (~500 CVE) pèse environ 2 Mo en HTML.
  Configure `keywords` / `min_cvss` pour un rapport ciblé.

## Usage responsable

veille-vulns est un outil **défensif** : il aide à savoir quelles failles
corriger en priorité. Il ne récupère aucun code d'exploitation. Il indique
seulement si NVD référence un exploit public (oui/non). Les informations
proviennent de sources tierces et peuvent être incomplètes ou en retard :
vérifie toujours les bulletins des éditeurs avant d'agir.

## Licence

Code distribué sous **licence MIT** (voir [LICENSE](LICENSE)) : tu peux utiliser,
modifier et redistribuer ce code, y compris dans un projet commercial, à
condition de conserver la mention de copyright (« lisox ») et le texte de la
licence. Le logiciel est fourni sans garantie.

La licence MIT couvre **le code de l'outil**, pas les données des sources, qui
restent soumises à leurs propres conditions (ci-dessous).

## Mentions et attributions

This product uses the NVD API but is not endorsed or certified by the NVD.

| Source | Conditions |
|---|---|
| [NVD](https://nvd.nist.gov/) (NIST) | [conditions d'utilisation de l'API](https://nvd.nist.gov/developers/terms-of-use) — mention ci-dessus obligatoire |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | données publiques du gouvernement américain |
| [FIRST EPSS](https://www.first.org/epss/) | réutilisation libre avec citation de FIRST.org |
| [CERT-FR](https://cert.cyber.gouv.fr/) (ANSSI) | [Licence Ouverte / Etalab 2.0](https://www.etalab.gouv.fr/licence-ouverte-open-licence/) — source citée dans les rapports |
| [CVE.org](https://www.cve.org/) | [conditions d'utilisation du programme CVE](https://www.cve.org/Legal/TermsOfUse) |
| [OSV](https://osv.dev/) | données sous licences des bases d'origine (CC-BY 4.0 pour la majorité) |
| [CWE](https://cwe.mitre.org/) (MITRE) | © The MITRE Corporation, [réutilisation autorisée](https://cwe.mitre.org/about/termsofuse.html) avec mention |

CVE® et CWE™ sont des marques de The MITRE Corporation.

## Auteur

Conçu et maintenu par **lisox** — [github.com/Lisox400](https://github.com/Lisox400).
