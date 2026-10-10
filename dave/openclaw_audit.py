"""Contrôles OpenClaw : configuration de la passerelle et audit natif optionnel.

Sources : documentation officielle (docs.openclaw.ai). La passerelle écoute par défaut sur
127.0.0.1:18789 ; les modes de bind non-loopback élargissent la surface d'attaque.
Le fichier de configuration peut être en JSON5 (commentaires, clés sans guillemets) :
on lit donc la clé gateway.bind par expression régulière, sans interpréter le reste.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .findings import Finding
from .rules import text

DEFAULT_CONFIG = Path.home() / ".openclaw" / "openclaw.json"
GATEWAY_RE = re.compile(r"""["']?gateway["']?\s*:\s*\{""")
BIND_RE = re.compile(r"""["']?bind["']?\s*:\s*["']([a-zA-Z]+)["']""")
PORT_RE = re.compile(r"""["']?port["']?\s*:\s*(\d{2,5})""")
SEVERITY = {"lan": "medium", "custom": "medium", "tailnet": "low"}


def _strip_comments(raw: str) -> str:
    raw = re.sub(r"/\*.*?\*/", "", raw, flags=re.S)
    return re.sub(r"(^|\s)//[^\n]*", r"\1", raw)


STRING_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')


def _neutralize_strings(raw: str) -> str:
    """Les accolades dans les chaînes (ex. "${TOKEN}") ne doivent pas compter comme structure."""
    return STRING_RE.sub(lambda m: m.group(0).replace("{", "(").replace("}", ")"), raw)


def _gateway_block(raw: str) -> tuple[str, int] | None:
    m = GATEWAY_RE.search(raw)
    if not m:
        return None
    depth, start = 0, m.end() - 1
    for i in range(start, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                return raw[start:i + 1], start
    return raw[start:], start


def audit_config(path: Path | None = None, lang: str = "en") -> list[Finding]:
    path = path or DEFAULT_CONFIG
    if not path.is_file():
        return []
    original = path.read_text(encoding="utf-8", errors="replace")
    raw = _neutralize_strings(_strip_comments(original))
    block = _gateway_block(raw)
    if not block:
        return []
    body, _ = block
    # ignorer les sous-objets (auth, controlUi, remote...) : seul le bind de premier niveau compte
    top = body[1:-1]
    for _ in range(50):  # aplatit les sous-objets, de l'intérieur vers l'extérieur
        flat = re.sub(r"\{[^{}]*\}", "()", top)
        if flat == top:
            break
        top = flat
    bind_m = BIND_RE.search(top)
    if not bind_m:
        return []
    bind = bind_m.group(1).lower()
    if bind not in SEVERITY:
        return []
    port_m = PORT_RE.search(top)
    port = port_m.group(1) if port_m else "18789"
    line = next((i for i, l in enumerate(original.splitlines(), 1) if BIND_RE.search(l)), None)
    title, detail, fix = text("DV013", lang, source=str(path), bind=bind, port=port)
    return [Finding("DV013", SEVERITY[bind], title, detail, fix, str(path), "OpenClaw gateway", line,
                    evidence=f'gateway.bind: "{bind}"')]


def native_audit(lang: str = "en", timeout: int = 60, binary: str | None = None) -> list[Finding]:
    """Lance 'openclaw security audit' si disponible. Sortie rapportée telle quelle, non interprétée."""
    exe = binary or shutil.which("openclaw")
    if not exe:
        return []
    try:
        proc = subprocess.run([exe, "security", "audit"], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    output = (proc.stdout + proc.stderr).strip()
    excerpt = "\n".join(output.splitlines()[:60])
    title, detail, fix = text("DV105", lang, code=proc.returncode)
    return [Finding("DV105", "info", title, detail, fix, "openclaw security audit", "OpenClaw", evidence=excerpt)]
