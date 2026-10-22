"""Décodage d'un vecteur CVSS (3.0, 3.1, 4.0, 2.0) en phrases claires en français.

Spécifications : https://www.first.org/cvss/
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CvssExplanation:
    version: str
    summary: str                                        # une phrase de synthèse
    details: list[tuple[str, str]] = field(default_factory=list)  # (aspect, explication)
    warning: str = ""                                   # lecture opérationnelle (scénario critique…)


# --- Textes communs ------------------------------------------------------------------

_ATTACK_VECTOR = {
    "N": ("à distance par le réseau",
          "Réseau : exploitable à distance, y compris depuis Internet si le service est exposé"),
    "A": ("depuis le réseau local",
          "Réseau adjacent : l'attaquant doit être sur le même réseau local (LAN, Wi-Fi, Bluetooth, VPN…)"),
    "L": ("avec un accès local",
          "Local : l'attaquant doit déjà avoir un accès au système (session, shell) "
          "ou amener un utilisateur à ouvrir un fichier piégé"),
    "P": ("avec un accès physique",
          "Physique : l'attaquant doit manipuler physiquement l'équipement (USB, port de debug…)"),
}

_PRIVILEGES = {
    "N": ("sans authentification", "Aucun : pas besoin de compte, l'attaque est non authentifiée"),
    "L": ("avec un compte utilisateur standard", "Faibles : un compte utilisateur ordinaire suffit"),
    "H": ("avec des droits d'administration", "Élevés : des droits d'administrateur sont nécessaires"),
}

_IMPACT_LEVEL = {"H": "élevé", "L": "limité", "N": "aucun"}

_IMPACT_DETAIL = {
    "C": {
        "H": "Élevé : accès à toutes les données ou à des données critiques (mots de passe, clés…)",
        "L": "Limité : accès partiel à certaines données, sans maîtrise de ce qui est obtenu",
        "N": "Aucun",
    },
    "I": {
        "H": "Élevé : modification de n'importe quelle donnée, voire prise de contrôle",
        "L": "Limité : modification de certaines données, sans contrôle total",
        "N": "Aucun",
    },
    "A": {
        "H": "Élevé : interruption complète du service (déni de service)",
        "L": "Limité : dégradation des performances ou interruption partielle",
        "N": "Aucun",
    },
}

_CIA_NAMES = {"C": "la confidentialité", "I": "l'intégrité", "A": "la disponibilité"}
_CIA_LABELS = {"C": "Confidentialité", "I": "Intégrité", "A": "Disponibilité"}


def explain(vector: str) -> CvssExplanation | None:
    """Renvoie None si le vecteur est vide ou illisible."""
    if not vector:
        return None
    version, metrics = parse_vector(vector)
    if not metrics:
        return None
    if version.startswith("4"):
        return _explain_v4(metrics)
    if version.startswith("3"):
        return _explain_v3(version, metrics)
    if "Au" in metrics:
        return _explain_v2(metrics)
    return None


def parse_vector(vector: str) -> tuple[str, dict[str, str]]:
    parts = [p for p in vector.strip().split("/") if p]
    version = "2.0"
    if parts and parts[0].upper().startswith("CVSS:"):
        version = parts.pop(0).split(":", 1)[1]
    metrics = {}
    for part in parts:
        key, sep, value = part.partition(":")
        if sep:
            metrics[key] = value
    return version, metrics


# --- CVSS 3.x ------------------------------------------------------------------------


def _explain_v3(version: str, m: dict[str, str]) -> CvssExplanation:
    details: list[tuple[str, str]] = []
    if av := _ATTACK_VECTOR.get(m.get("AV", "")):
        details.append(("Vecteur d'attaque", av[1]))
    details.append(("Complexité", {
        "L": "Faible : aucune condition particulière, l'attaque est reproductible à volonté",
        "H": "Élevée : l'attaque dépend de conditions hors du contrôle de l'attaquant "
             "(configuration particulière, situation de concurrence, position d'interception…)",
    }.get(m.get("AC", ""), "?")))
    if pr := _PRIVILEGES.get(m.get("PR", "")):
        details.append(("Privilèges requis", pr[1]))
    details.append(("Interaction", {
        "N": "Aucune : l'attaque fonctionne sans action de la victime",
        "R": "Requise : la victime doit agir (cliquer sur un lien, ouvrir un fichier, visiter une page…)",
    }.get(m.get("UI", ""), "?")))
    details.append(("Portée", {
        "U": "Inchangée : l'impact reste limité au composant vulnérable",
        "C": "Changée : l'attaque déborde du composant vulnérable "
             "(sortie de sandbox ou de VM, XSS touchant le navigateur, rebond vers d'autres systèmes…)",
    }.get(m.get("S", ""), "?")))
    for key in "CIA":
        if key in m:
            details.append((_CIA_LABELS[key], _IMPACT_DETAIL[key].get(m[key], "?")))
    if maturity := _maturity_v3(m.get("E", "X")):
        details.append(("Maturité de l'exploit", maturity))

    summary = _summary(
        m.get("AV"), m.get("PR"), m.get("UI") == "N", "faible" if m.get("AC") == "L" else "élevée",
        {k: m.get(k, "N") for k in "CIA"},
        scope_changed=m.get("S") == "C",
    )
    return CvssExplanation(version, summary, details, _warning(m.get("AV"), m.get("PR"), m.get("UI") == "N", m))


def _maturity_v3(value: str) -> str:
    return {
        "U": "Non prouvée : aucun code d'exploitation connu",
        "P": "Preuve de concept disponible",
        "F": "Exploit fonctionnel disponible",
        "H": "Exploitation fiable ou automatisée (outils, vers)",
    }.get(value, "")


# --- CVSS 4.0 ------------------------------------------------------------------------


def _explain_v4(m: dict[str, str]) -> CvssExplanation:
    details: list[tuple[str, str]] = []
    if av := _ATTACK_VECTOR.get(m.get("AV", "")):
        details.append(("Vecteur d'attaque", av[1]))
    details.append(("Complexité", {
        "L": "Faible : aucune protection spécifique à contourner",
        "H": "Élevée : l'attaquant doit contourner des protections (ASLR, DEP…) ou obtenir un secret",
    }.get(m.get("AC", ""), "?")))
    details.append(("Prérequis", {
        "N": "Aucun : l'attaque ne dépend d'aucune condition de déploiement particulière",
        "P": "Présents : conditions particulières nécessaires (configuration, situation de concurrence, "
             "position d'interception sur le réseau…)",
    }.get(m.get("AT", ""), "?")))
    if pr := _PRIVILEGES.get(m.get("PR", "")):
        details.append(("Privilèges requis", pr[1]))
    details.append(("Interaction", {
        "N": "Aucune : l'attaque fonctionne sans action de la victime",
        "P": "Passive : la victime doit seulement faire une action ordinaire (consulter une page, un e-mail)",
        "A": "Active : la victime doit faire une action volontaire (ouvrir un fichier, accepter un avertissement…)",
    }.get(m.get("UI", ""), "?")))
    for key in "CIA":
        if f"V{key}" in m:
            details.append((_CIA_LABELS[key], _IMPACT_DETAIL[key].get(m[f"V{key}"], "?")))
    subsequent = [_CIA_NAMES[k] for k in "CIA" if m.get(f"S{k}") in ("H", "L", "S")]
    if subsequent:
        details.append(("Systèmes tiers", f"impact aussi sur {_join(subsequent)} d'autres systèmes "
                        "que le composant vulnérable"))
    if maturity := {
        "A": "Attaques constatées (exploitation active signalée)",
        "P": "Preuve de concept publique",
        "U": "Aucune exploitation ni preuve de concept signalée",
    }.get(m.get("E", "X"), ""):
        details.append(("Maturité de l'exploit", maturity))

    summary = _summary(
        m.get("AV"), m.get("PR"), m.get("UI") == "N", "faible" if m.get("AC") == "L" and m.get("AT") == "N" else "élevée",
        {k: m.get(f"V{k}", "N") for k in "CIA"},
        scope_changed=bool(subsequent),
    )
    impacts = {k: m.get(f"V{k}", "N") for k in "CIA"}
    return CvssExplanation("4.0", summary, details, _warning(m.get("AV"), m.get("PR"), m.get("UI") == "N", impacts))


# --- CVSS 2.0 ------------------------------------------------------------------------


def _explain_v2(m: dict[str, str]) -> CvssExplanation:
    av = {"N": "N", "A": "A", "L": "L"}.get(m.get("AV", ""))
    pr = {"N": "N", "S": "L", "M": "H"}.get(m.get("Au", ""))
    impacts = {k: {"C": "H", "P": "L", "N": "N"}.get(m.get(k, "N"), "N") for k in "CIA"}
    details: list[tuple[str, str]] = []
    if av:
        details.append(("Vecteur d'attaque", _ATTACK_VECTOR[av][1]))
    details.append(("Complexité", {
        "L": "Faible : aucune condition particulière",
        "M": "Moyenne : quelques conditions nécessaires (configuration non standard, action de la victime…)",
        "H": "Élevée : conditions très spécifiques nécessaires",
    }.get(m.get("AC", ""), "?")))
    details.append(("Authentification", {
        "N": "Aucune : l'attaque est non authentifiée",
        "S": "Une authentification nécessaire",
        "M": "Plusieurs authentifications nécessaires",
    }.get(m.get("Au", ""), "?")))
    for key in "CIA":
        level = {"C": "Complet", "P": "Partiel", "N": "Aucun"}.get(m.get(key, ""), "?")
        details.append((_CIA_LABELS[key], level))
    summary = _summary(av, pr, None, {"L": "faible", "M": "moyenne"}.get(m.get("AC", ""), "élevée"), impacts)
    # Pas d'avertissement : CVSS 2 ne dit pas si une action de la victime est nécessaire.
    return CvssExplanation("2.0", summary, details)


# --- Synthèse ------------------------------------------------------------------------


def _summary(
    av: str | None,
    pr: str | None,
    no_interaction: bool | None,
    complexity: str,
    impacts: dict[str, str],
    scope_changed: bool = False,
) -> str:
    conditions = []
    if pr in _PRIVILEGES:
        conditions.append(_PRIVILEGES[pr][0])
    if no_interaction is True:
        conditions.append("sans interaction de l'utilisateur")
    elif no_interaction is False:
        conditions.append("en piégeant un utilisateur")
    first = "Exploitable " + (_ATTACK_VECTOR[av][0] if av in _ATTACK_VECTOR else "")
    if conditions:
        first += ", " + ", ".join(conditions)
    first += f", complexité {complexity}."

    high = [_CIA_NAMES[k] for k in "CIA" if impacts.get(k) == "H"]
    low = [_CIA_NAMES[k] for k in "CIA" if impacts.get(k) == "L"]
    parts = []
    if high:
        parts.append(f"impact élevé sur {_join(high)}")
    if low:
        parts.append(f"impact limité sur {_join(low)}")
    second = (" ; ".join(parts) if parts else "aucun impact direct déclaré").capitalize()
    if scope_changed:
        second += ", au-delà du composant vulnérable"
    return f"{first} {second}."


def _warning(av: str | None, pr: str | None, no_interaction: bool, impacts: dict[str, str]) -> str:
    high = [k for k in "CIA" if impacts.get(k) == "H"]
    if av == "N" and pr == "N" and no_interaction and high:
        return ("Scénario critique : attaque à distance, non authentifiée et sans action de la victime — "
                "exploitable en masse (scans Internet, vers). Priorité maximale si le service est exposé.")
    if av == "N" and pr == "N" and high:
        return "Attaque à distance sans compte : seule une action de la victime fait obstacle (hameçonnage)."
    return ""


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " et " + items[-1]
