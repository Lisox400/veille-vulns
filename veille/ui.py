"""Rendu terminal : couleurs ANSI, bannière, messages [+] [*] [!] [-], progression.

Les couleurs sont désactivées si la sortie n'est pas un terminal, si la
variable NO_COLOR est définie (https://no-color.org) ou avec --no-color.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys

from . import __version__

_RESET = "\033[0m"
_CODES = {
    "bold": "1", "dim": "2", "italic": "3", "underline": "4",
    "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36",
    "white": "37", "gray": "90", "bred": "91", "bgreen": "92", "byellow": "93", "bblue": "94",
    "bmagenta": "95", "bcyan": "96",
    "on_red": "41", "on_yellow": "43", "on_green": "42", "on_blue": "44", "on_magenta": "45",
}

_color = False

BANNER = r"""
 ██╗   ██╗███████╗██╗██╗     ██╗     ███████╗
 ██║   ██║██╔════╝██║██║     ██║     ██╔════╝
 ██║   ██║█████╗  ██║██║     ██║     █████╗
 ╚██╗ ██╔╝██╔══╝  ██║██║     ██║     ██╔══╝
  ╚████╔╝ ███████╗██║███████╗███████╗███████╗
   ╚═══╝  ╚══════╝╚═╝╚══════╝╚══════╝╚══════╝"""


def init(color: bool | None = None) -> None:
    """Active l'UTF-8 et, si possible, les couleurs ANSI (y compris sous Windows)."""
    global _color
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    _color = color and _enable_windows_ansi()


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        enable_vt = 0x0004
        for handle_id in (-11, -12):  # stdout, stderr
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | enable_vt)
        return True
    except (AttributeError, OSError):
        return False


def c(text: object, *styles: str) -> str:
    if not _color or not styles:
        return str(text)
    codes = ";".join(_CODES[s] for s in styles)
    return f"\033[{codes}m{text}{_RESET}"


def width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 160))


AUTHOR = "lisox"


def banner() -> None:
    sys.stdout.flush()
    print(c(BANNER, "bred", "bold"), file=sys.stderr)
    signature = c("  ──────────────[ ", "gray") + c("coded by ", "gray") + c(AUTHOR, "bold", "bgreen") \
        + c(" ]──────────────", "gray") + c(f"  v{__version__}", "bcyan")
    print(signature, file=sys.stderr)
    print(c("  vuln-watch // NVD · KEV · EPSS · CERT-FR · OSV · CVE.org · CWE", "gray"), file=sys.stderr)
    print(file=sys.stderr)


# --- Messages ------------------------------------------------------------------


def ok(message: str) -> None:
    _clear_progress()
    print(f"{c('[+]', 'bgreen', 'bold')} {message}", file=sys.stderr)


def info(message: str) -> None:
    _clear_progress()
    print(f"{c('[*]', 'bblue', 'bold')} {message}", file=sys.stderr)


def warn(message: str) -> None:
    _clear_progress()
    print(f"{c('[!]', 'byellow', 'bold')} {message}", file=sys.stderr)


def error(message: str) -> None:
    _clear_progress()
    print(f"{c('[-]', 'bred', 'bold')} {message}", file=sys.stderr)


def section(title: str) -> None:
    line = "─" * max(4, width() - len(title) - 6)
    print(f"\n{c('──[', 'gray')} {c(title, 'bold', 'bcyan')} {c(']' + line, 'gray')}")


class LogFormatter(logging.Formatter):
    """Affiche les journaux avec les mêmes préfixes que les messages de l'outil."""

    _PREFIX = {
        logging.DEBUG: ("[d]", "gray"),
        logging.INFO: ("[*]", "bblue"),
        logging.WARNING: ("[!]", "byellow"),
        logging.ERROR: ("[-]", "bred"),
        logging.CRITICAL: ("[-]", "bred"),
    }

    def format(self, record: logging.LogRecord) -> str:
        _clear_progress()
        prefix, color = self._PREFIX.get(record.levelno, ("[?]", "white"))
        message = super().format(record)
        if record.levelno == logging.DEBUG:
            message = c(message, "gray")
        return f"{c(prefix, color, 'bold')} {message}"


# --- Progression -----------------------------------------------------------------

_progress_active = False


def progress(label: str, done: int, total: int) -> None:
    """Barre de progression sur stderr (seulement dans un terminal)."""
    global _progress_active
    if not sys.stderr.isatty() or total <= 1:
        return
    sys.stdout.flush()
    bar_width = 28
    filled = int(bar_width * done / total)
    bar = c("█" * filled, "bgreen") + c("░" * (bar_width - filled), "gray")
    sys.stderr.write(f"\r{c('[~]', 'bmagenta', 'bold')} {label:<8} {bar} {done}/{total} ")
    sys.stderr.flush()
    _progress_active = done < total
    if done >= total:
        sys.stderr.write("\r\033[K" if _color else "\r" + " " * (bar_width + 40) + "\r")
        sys.stderr.flush()


def _clear_progress() -> None:
    global _progress_active
    sys.stdout.flush()  # garde l'ordre stdout/stderr quand la sortie est redirigée
    if _progress_active:
        sys.stderr.write("\r\033[K" if _color else "\n")
        _progress_active = False


# --- Badges -------------------------------------------------------------------------

_SEVERITY_STYLE = {
    "CRITICAL": ("CRIT", ("bold", "white", "on_red")),
    "HIGH": ("HIGH", ("bold", "bred")),
    "MEDIUM": ("MED ", ("byellow",)),
    "LOW": ("LOW ", ("bgreen",)),
    "NONE": ("NONE", ("gray",)),
}


def severity(level: str | None, score: float | None) -> str:
    if score is None or not level:
        return c(" n/a     ", "gray")
    label, styles = _SEVERITY_STYLE.get(level, (level[:4], ("white",)))
    return c(f"{score:>4.1f} {label}", *styles)


def epss(score: float | None) -> str:
    if score is None:
        return c("   n/a", "gray")
    text = f"{score * 100:>5.1f}%" if score >= 0.001 else " <0.1%"
    if score >= 0.5:
        return c(text, "bold", "bred")
    if score >= 0.1:
        return c(text, "byellow")
    return c(text, "gray")


def tag(text: str, style: str) -> str:
    return c(f"[{text}]", "bold", style)


def yes_no(value: bool, yes: str = "OUI", no: str = "non", danger: bool = True) -> str:
    if value:
        return c(yes, "bold", "bred" if danger else "bgreen")
    return c(no, "gray")


# --- Menus interactifs ----------------------------------------------------------------


class Back(Exception):
    """L'utilisateur a demandé à quitter (Ctrl+C / fin d'entrée)."""


def clear() -> None:
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def menu_item(key: str, label: str, hint: str = "", width: int = 32) -> None:
    hint_text = c(hint, "gray") if hint else ""
    print(f"  {c('[', 'gray')}{c(key, 'bold', 'bgreen')}{c(']', 'gray')} {label:<{width}} {hint_text}")


def ask(prompt: str = "veille", default: str = "") -> str:
    """Invite façon shell : `veille > `. Ctrl+C ou fin d'entrée → Back."""
    suffix = c(f" [{default}]", "gray") if default else ""
    try:
        answer = input(f"\n{c(prompt, 'bold', 'bred')}{suffix} {c('>', 'bold', 'bgreen')} ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise Back from None
    return answer or default


def pause() -> None:
    try:
        input(c("\n  [Entrée] pour continuer", "gray"))
    except (EOFError, KeyboardInterrupt):
        print()
        raise Back from None
