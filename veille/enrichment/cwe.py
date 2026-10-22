"""Présentation en français des informations CWE (libellés énumérés du catalogue).

Le catalogue MITRE est en anglais. Sans traduction automatique, seuls les
libellés issus de listes fermées (phases, portées, impacts, efficacité) sont
traduits ; les noms et descriptions restent en anglais.
"""

from __future__ import annotations

from ..models import CweInfo, CweMitigation

PHASES = {
    "Requirements": "Exigences",
    "Architecture and Design": "Conception",
    "Implementation": "Implémentation",
    "Build and Compilation": "Compilation",
    "Testing": "Tests",
    "Documentation": "Documentation",
    "Bundling": "Packaging",
    "Distribution": "Distribution",
    "Installation": "Installation",
    "System Configuration": "Configuration",
    "Operation": "Exploitation",
    "Patching and Maintenance": "Maintenance",
    "Porting": "Portage",
    "Integration": "Intégration",
    "Manufacturing": "Fabrication",
    "Policy": "Politique",
    "Decommissioning and End-of-Life": "Fin de vie",
}

STRATEGIES = {
    "Attack Surface Reduction": "réduction de la surface d'attaque",
    "Compilation or Build Hardening": "durcissement de la compilation",
    "Enforcement by Conversion": "conversion de type",
    "Environment Hardening": "durcissement de l'environnement",
    "Firewall": "pare-feu",
    "Input Validation": "validation des entrées",
    "Language Selection": "choix du langage",
    "Libraries or Frameworks": "bibliothèques ou frameworks",
    "Output Encoding": "encodage des sorties",
    "Parameterization": "paramétrage (requêtes préparées)",
    "Refactoring": "refactorisation",
    "Resource Limitation": "limitation des ressources",
    "Sandbox or Jail": "bac à sable",
    "Separation of Privilege": "séparation des privilèges",
    "Identify and Reduce Attack Surface": "réduction de la surface d'attaque",
}

SCOPES = {
    "Confidentiality": "Confidentialité",
    "Integrity": "Intégrité",
    "Availability": "Disponibilité",
    "Access Control": "Contrôle d'accès",
    "Accountability": "Traçabilité",
    "Authentication": "Authentification",
    "Authorization": "Autorisation",
    "Non-Repudiation": "Non-répudiation",
    "Other": "Autre",
}

IMPACTS = {
    "Execute Unauthorized Code or Commands": "exécution de code ou de commandes",
    "Gain Privileges or Assume Identity": "élévation de privilèges ou usurpation d'identité",
    "Bypass Protection Mechanism": "contournement de protections",
    "Read Application Data": "lecture de données applicatives",
    "Modify Application Data": "modification de données applicatives",
    "Read Files or Directories": "lecture de fichiers",
    "Modify Files or Directories": "modification de fichiers",
    "Read Memory": "lecture mémoire",
    "Modify Memory": "corruption mémoire",
    "DoS: Crash, Exit, or Restart": "déni de service (plantage, redémarrage)",
    "DoS: Instability": "déni de service (instabilité)",
    "DoS: Amplification": "déni de service (amplification)",
    "DoS: Resource Consumption (CPU)": "déni de service (CPU)",
    "DoS: Resource Consumption (Memory)": "déni de service (mémoire)",
    "DoS: Resource Consumption (Other)": "déni de service (ressources)",
    "Hide Activities": "dissimulation d'activité",
    "Alter Execution Logic": "détournement de la logique d'exécution",
    "Unexpected State": "état inattendu",
    "Quality Degradation": "dégradation de la qualité",
    "Varies by Context": "variable selon le contexte",
    "Reduce Maintainability": "maintenabilité réduite",
    "Reduce Performance": "performances réduites",
    "Reduce Reliability": "fiabilité réduite",
    "Other": "autre",
}

LEVELS = {
    "High": "élevée", "Medium": "moyenne", "Moderate": "moyenne", "Low": "faible",
    "Limited": "limitée", "Defense in Depth": "défense en profondeur", "None": "aucune",
    "Incidental": "indirecte", "Discouraged Common Practice": "pratique déconseillée",
}


def likelihood_fr(info: CweInfo) -> str:
    return LEVELS.get(info.likelihood, info.likelihood)


def consequences_fr(info: CweInfo, limit: int = 4) -> list[str]:
    """Une ligne par conséquence : « Confidentialité, Intégrité → lecture de données… »."""
    lines = []
    for consequence in info.consequences[:limit]:
        scopes = ", ".join(SCOPES.get(s, s) for s in consequence.scopes)
        impacts = ", ".join(IMPACTS.get(i, i) for i in consequence.impacts)
        if scopes or impacts:
            lines.append(f"{scopes} → {impacts}" if scopes and impacts else scopes or impacts)
    return lines


def mitigation_label(mitigation: CweMitigation) -> str:
    """« Conception · bibliothèques ou frameworks · efficacité élevée »."""
    parts = [", ".join(PHASES.get(p, p) for p in mitigation.phases)]
    if mitigation.strategy:
        parts.append(STRATEGIES.get(mitigation.strategy, mitigation.strategy))
    if mitigation.effectiveness:
        parts.append(f"efficacité {LEVELS.get(mitigation.effectiveness, mitigation.effectiveness)}")
    return " · ".join(p for p in parts if p)


# Beaucoup de mesures essentielles (requêtes préparées…) ne sont pas notées :
# « non noté » est traité comme « moyenne », l'ordre du catalogue départage.
_EFFECTIVENESS_RANK = {"High": 0, "Moderate": 1, "": 1, "Limited": 2, "Defense in Depth": 3,
                       "Incidental": 4, "Discouraged Common Practice": 5}


def top_mitigations(info: CweInfo, limit: int = 3) -> list[CweMitigation]:
    """Mesures les plus efficaces d'abord, ordre du catalogue sinon."""
    ranked = sorted(
        enumerate(info.mitigations),
        key=lambda item: (_EFFECTIVENESS_RANK.get(item[1].effectiveness, 2), item[0]),
    )
    return [m for _, m in ranked[:limit]]
