"""Audit des configurations de clients MCP (Claude Desktop, Cursor, VS Code, .mcp.json)."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .compose_audit import INTERPOLATION_RE, SECRET_KEY_RE
from .findings import Finding
from .rules import text

HOME = Path.home()
GLOBAL_CONFIGS = [
    HOME / "Library/Application Support/Claude/claude_desktop_config.json",
    HOME / ".config/Claude/claude_desktop_config.json",
    Path(os.environ.get("APPDATA", HOME / "AppData/Roaming")) / "Claude/claude_desktop_config.json",
    HOME / ".cursor/mcp.json",
]
PROJECT_CONFIGS = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"]
REF_RE = re.compile(r"^\$\{?(env:)?[A-Za-z_][A-Za-z0-9_]*\}?$|^\$\{input:")


def config_files(project: Path | None) -> list[Path]:
    files = [p for p in GLOBAL_CONFIGS if p.is_file()]
    if project:
        files += [project / rel for rel in PROJECT_CONFIGS if (project / rel).is_file()]
    return files


def _too_broad(path: str) -> bool:
    p = path.strip().rstrip("/\\") or "/"
    if p in ("/", "~", "$HOME", "${HOME}", "%USERPROFILE%") or re.fullmatch(r"[A-Za-z]:\\?", p):
        return True
    try:
        return Path(os.path.expanduser(p)).resolve() in (HOME.resolve(), Path("/"))
    except OSError:
        return False


def audit_mcp_config(path: Path, lang: str = "en") -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    servers = data.get("mcpServers") or data.get("servers") or {}
    findings = []
    for name, srv in servers.items() if isinstance(servers, dict) else []:
        if not isinstance(srv, dict):
            continue
        for key, val in (srv.get("env") or {}).items():
            val = str(val).strip()
            if SECRET_KEY_RE.search(key) and val and not REF_RE.match(val) and not INTERPOLATION_RE.match(val):
                title, detail, fix = text("DV015", lang, source=str(path), service=name, key=key)
                findings.append(Finding("DV015", "medium", title, detail, fix, str(path), name, evidence=f"{key}=****"))
        args = [str(a) for a in srv.get("args") or []]
        if any("server-filesystem" in a for a in args + [str(srv.get("command", ""))]):
            for a in args:
                if "server-filesystem" in a or a.startswith("-"):
                    continue
                if _too_broad(a):
                    title, detail, fix = text("DV016", lang, source=str(path), service=name, path=a)
                    findings.append(Finding("DV016", "high", title, detail, fix, str(path), name, evidence=f"allowed: {a}"))
    return findings
