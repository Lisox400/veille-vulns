"""Utilitaires de texte communs au terminal et au rapport."""

from __future__ import annotations

import re


def markdown_to_text(text: str) -> str:
    """Markdown → texte brut lisible."""
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.M)
    text = re.sub(r"\*\*(.+?)\*\*|__(.+?)__", lambda m: m.group(1) or m.group(2), text, flags=re.S)
    text = re.sub(r"(?<!\w)\*(\S.*?)\*(?!\w)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\((\S+)\)", r"\1 (\2)", text)
    return re.sub(r"\\([\\`*_{}\[\]()#+\-.!])", r"\1", text)


def paragraphs(text: str) -> list[str]:
    """Découpe en paragraphes (lignes vides ou puces), espaces normalisés."""
    parts = re.split(r"\n\s*\n|\n(?=\s*[-*•] )", text)
    return [" ".join(p.split()) for p in parts if p.strip()]


def solution_paragraphs(solution_markdown: str) -> list[str]:
    """Section Solution/Contournement d'un avis CERT-FR, sans les titres."""
    body = "\n".join(line for line in solution_markdown.splitlines() if not line.startswith("#"))
    return paragraphs(markdown_to_text(body))


def shorten(text: str, size: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= size else text[: size - 1].rsplit(" ", 1)[0] + " …"
