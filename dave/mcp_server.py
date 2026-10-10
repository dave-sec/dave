"""Serveur MCP (stdio, JSON-RPC 2.0) : expose Dave aux agents IA.

Principes de sécurité :
- lecture seule : aucun outil ne modifie de fichier (les correctifs ne sont proposés qu'en diff) ;
- fichiers limités à un dossier racine (DAVE_MCP_ROOT, par défaut le dossier courant) ;
- sondes réseau limitées aux hôtes autorisés (DAVE_MCP_ALLOWED_HOSTS, par défaut 127.0.0.1),
  pour qu'un agent manipulé par injection de prompt ne puisse pas scanner n'importe quoi.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import __version__
from .compose_audit import audit_compose, find_compose_files
from .fixer import FIXABLE, fix_file
from .host_audit import audit_host
from .network_probe import probe
from .openclaw_audit import audit_config
from .report import score, sort_findings
from .rules import RULES

SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

TOOLS = [
    {
        "name": "dave_scan_compose",
        "description": "Audit docker-compose files of a self-hosted AI stack (Ollama, Open WebUI, OpenClaw, Qdrant...). Read-only. Returns findings and an A-F grade.",
        "inputSchema": {"type": "object", "properties": {
            "path": {"type": "string", "description": "File or directory, relative to the allowed root"},
            "lang": {"type": "string", "enum": ["en", "fr"]}}, "required": ["path"]},
    },
    {
        "name": "dave_fix_preview",
        "description": "Preview safe automatic fixes for a compose file as a unified diff. Never writes: a human applies them with 'dave fix --write'.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    {
        "name": "dave_host_audit",
        "description": "Audit this machine: Ollama systemd install and OpenClaw gateway configuration. Read-only.",
        "inputSchema": {"type": "object", "properties": {"lang": {"type": "string", "enum": ["en", "fr"]}}},
    },
    {
        "name": "dave_probe",
        "description": "Probe an allowed host for exposed AI services (TCP connect and read-only HTTP GET). Only hosts listed by the user in DAVE_MCP_ALLOWED_HOSTS are accepted.",
        "inputSchema": {"type": "object", "properties": {
            "host": {"type": "string"}, "lang": {"type": "string", "enum": ["en", "fr"]}}, "required": ["host"]},
    },
    {
        "name": "dave_rule",
        "description": "Explain a Dave rule (severity, fix, references) by its ID, for example DV001.",
        "inputSchema": {"type": "object", "properties": {"rule_id": {"type": "string"}}, "required": ["rule_id"]},
    },
]


class ToolError(Exception):
    pass


class Server:
    def __init__(self, root: Path | None = None, allowed_hosts: set[str] | None = None):
        self.root = (root or Path(os.environ.get("DAVE_MCP_ROOT", "."))).resolve()
        env_hosts = os.environ.get("DAVE_MCP_ALLOWED_HOSTS", "127.0.0.1")
        self.allowed_hosts = allowed_hosts or {h.strip() for h in env_hosts.split(",") if h.strip()}

    def _path(self, raw: str) -> Path:
        candidate = (self.root / raw).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ToolError(f"Path outside the allowed root ({self.root}).")
        if not candidate.exists():
            raise ToolError(f"Not found: {raw}")
        return candidate

    @staticmethod
    def _report(findings) -> str:
        value, grade = score(findings)
        return json.dumps({"grade": grade, "score": value,
                           "findings": [f.to_dict() for f in sort_findings(findings)]},
                          ensure_ascii=False, indent=2)

    def call(self, name: str, args: dict) -> str:
        lang = args.get("lang", "en") if args.get("lang") in ("en", "fr") else "en"
        if name == "dave_scan_compose":
            target = self._path(str(args.get("path", ".")))
            files = find_compose_files(target) if target.is_dir() else [target]
            findings = [f for path in files for f in audit_compose(path, lang)]
            return self._report(findings)
        if name == "dave_fix_preview":
            target = self._path(str(args.get("path", "")))
            if target.is_dir():
                raise ToolError("Give a compose file, not a directory.")
            fixable = [f for f in audit_compose(target) if f.rule_id in FIXABLE]
            return fix_file(target, fixable, write=False) or "Nothing to fix automatically."
        if name == "dave_host_audit":
            return self._report(audit_host(None, lang) + audit_config(None, lang))
        if name == "dave_probe":
            host = str(args.get("host", "")).strip()
            if host not in self.allowed_hosts:
                raise ToolError(f"Host not allowed. The user must add it to DAVE_MCP_ALLOWED_HOSTS (now: {', '.join(sorted(self.allowed_hosts))}).")
            return self._report(probe(host, lang=lang))
        if name == "dave_rule":
            rid = str(args.get("rule_id", "")).upper()
            if rid not in RULES:
                raise ToolError(f"Unknown rule {rid}.")
            r = RULES[rid]
            return json.dumps({"id": rid, "severity": r["severity"], "en": r["en"], "fr": r["fr"],
                               "references": r.get("refs", [])}, ensure_ascii=False, indent=2)
        raise ToolError(f"Unknown tool {name}.")

    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:  # notification (ex. notifications/initialized) : pas de réponse
            return None
        if method == "initialize":
            asked = (msg.get("params") or {}).get("protocolVersion")
            version = asked if asked in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
            result = {"protocolVersion": version, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "dave", "version": __version__}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                out = self.call(str(params.get("name")), params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": out}], "isError": False}
            except ToolError as exc:
                result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
            except Exception as exc:  # erreur inattendue : renvoyée proprement à l'agent
                result = {"content": [{"type": "text", "text": f"Internal error: {exc}"}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def serve(self, stdin=sys.stdin, stdout=sys.stdout) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            else:
                resp = self.handle(msg) if isinstance(msg, dict) else None
            if resp is not None:
                stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                stdout.flush()
