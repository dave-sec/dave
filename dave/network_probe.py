"""Sonde réseau légère sur une cible que l'utilisateur possède.

Uniquement des connexions TCP et une requête HTTP GET en lecture (/api/tags d'Ollama).
Aucune tentative d'exploitation.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request

from .advisories import matching
from .findings import Finding
from .rules import LOCAL_NOTE, text
from .services import PROBE_PORTS

CONNECT_TIMEOUT = 1.0
HTTP_TIMEOUT = 3.0


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def _get_json(host: str, port: int, path: str):
    url_host = f"[{host}]" if ":" in host else host
    req = urllib.request.Request(f"http://{url_host}:{port}{path}", headers={"User-Agent": "dave"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
    except (urllib.error.URLError, ValueError, OSError):
        return None


def ollama_version(host: str, port: int) -> str | None:
    data = _get_json(host, port, "/api/version")
    return str(data["version"]) if isinstance(data, dict) and data.get("version") else None


def qdrant_open(host: str, port: int) -> bool:
    data = _get_json(host, port, "/collections")
    return isinstance(data, dict) and isinstance(data.get("result"), dict) and "collections" in data["result"]


def ollama_models(host: str, port: int) -> int | None:
    """Nombre de modèles listés par /api/tags, ou None si ce n'est pas un Ollama ouvert."""
    url_host = f"[{host}]" if ":" in host else host
    req = urllib.request.Request(f"http://{url_host}:{port}/api/tags", headers={"User-Agent": "dave"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
    except (urllib.error.URLError, ValueError, OSError):
        return None
    if isinstance(data, dict) and isinstance(data.get("models"), list):
        return len(data["models"])
    return None


def probe(host: str, ports: dict[int, str] | None = None, lang: str = "en") -> list[Finding]:
    ports = ports or PROBE_PORTS
    local = is_loopback(host)
    findings: list[Finding] = []
    for port, service in sorted(ports.items()):
        if not port_open(host, port):
            continue
        target = f"{host}:{port}"
        count = ollama_models(host, port)
        if count is not None:
            title, detail, fix = text("DV101", lang, target=target, count=count)
            sev = "info" if local else "high"
            if local:
                detail += LOCAL_NOTE[lang]
            findings.append(Finding("DV101", sev, title, detail, fix, target, "Ollama",
                                    evidence=f"GET /api/tags -> 200, {count} model(s)"))
            version = ollama_version(host, port)
            for adv in matching("Ollama", version):
                title, detail, fix = text("DV103", lang, target=target, version=version,
                                          cve=adv["id"], fixed=adv["fixed"])
                findings.append(Finding("DV103", "critical", title, detail, fix, target, "Ollama",
                                        evidence=f"GET /api/version -> {version}"))
            continue
        if qdrant_open(host, port):
            title, detail, fix = text("DV104", lang, target=target)
            sev = "info" if local else "high"
            if local:
                detail += LOCAL_NOTE[lang]
            findings.append(Finding("DV104", sev, title, detail, fix, target, "Qdrant",
                                    evidence="GET /collections -> 200 without API key"))
            continue
        title, detail, fix = text("DV102", lang, port=port, service=service, target=host)
        sev = "info" if local else "medium"
        if local:
            detail += LOCAL_NOTE[lang]
        findings.append(Finding("DV102", sev, title, detail, fix, target, service, evidence="TCP connect OK"))
    return findings
