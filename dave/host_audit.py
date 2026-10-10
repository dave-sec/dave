"""Audit d'une installation d'Ollama directement sur l'hôte (service systemd)."""
from __future__ import annotations

import re
from pathlib import Path

from .findings import Finding
from .rules import text

SYSTEMD_PATHS = [
    Path("/etc/systemd/system/ollama.service"),
    Path("/etc/systemd/system/ollama.service.d"),
    Path("/lib/systemd/system/ollama.service"),
    Path("/usr/lib/systemd/system/ollama.service"),
]
HOST_RE = re.compile(r"""OLLAMA_HOST\s*=\s*["']?([^"'\s]+)""")
EXPOSED_PREFIXES = ("0.0.0.0", "::", "[::]", ":")


def _unit_files(paths: list[Path]) -> list[Path]:
    files = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(p.glob("*.conf")))
        elif p.is_file():
            files.append(p)
    return files


def audit_host(paths: list[Path] | None = None, lang: str = "en") -> list[Finding]:
    findings = []
    for f in _unit_files(paths or SYSTEMD_PATHS):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#"):
                continue
            m = HOST_RE.search(line)
            if m and m.group(1).startswith(EXPOSED_PREFIXES):
                title, detail, fix = text("DV012", lang, service=str(f), value=m.group(1))
                findings.append(Finding("DV012", "high", title, detail, fix, str(f), "ollama (systemd)", i,
                                        evidence=line.strip()))
    return findings
