"""Analyse statique de fichiers docker-compose."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from .advisories import matching
from .findings import Finding
from .rules import text
from .services import AI_SERVICES, SENSITIVE_PORTS, default_ports, identify

# docker-compose.yml, compose.yaml, docker-compose.prod.yml, compose.override.yaml...
COMPOSE_FILE_RE = re.compile(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$")
SECRET_KEY_RE = re.compile(r"(API_KEY|APIKEY|SECRET|TOKEN|PASSWORD|PASSWD)", re.IGNORECASE)
INTERPOLATION_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*")
IGNORE_RE = re.compile(r"#\s*dave:ignore\b([^\n]*)", re.IGNORECASE)
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
# Images vérifiées comme tournant en root par défaut. N'ajouter qu'avec une source.
ROOT_BY_DEFAULT = {"Ollama"}


def find_compose_files(root: Path) -> list[Path]:
    from .walk import walk_files
    return [p for p in walk_files(root) if COMPOSE_FILE_RE.match(p.name)]


def parse_port(entry) -> tuple[str | None, str | None, int | None]:
    """Renvoie (ip_hôte, port_hôte, port_conteneur) pour la syntaxe courte ou longue."""
    if isinstance(entry, dict):
        target = entry.get("target")
        published = entry.get("published")
        return entry.get("host_ip"), str(published) if published is not None else None, _to_int(target)
    raw = str(entry).split("/")[0].strip()
    host_ip = None
    if raw.startswith("["):  # IPv6 entre crochets
        end = raw.index("]")
        host_ip, raw = raw[1:end], raw[end + 2:]
    parts = raw.split(":")
    if len(parts) == 1:
        return host_ip, None, _to_int(parts[0])
    if len(parts) == 2:
        return host_ip, parts[0], _to_int(parts[1])
    return parts[0], parts[1], _to_int(parts[2])


def _to_int(value) -> int | None:
    try:
        return int(str(value).split("-")[0])
    except (TypeError, ValueError):
        return None


def _env(service: dict) -> dict[str, str]:
    env = service.get("environment") or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            key, _, val = str(item).partition("=")
            out[key.strip()] = val
        return out
    return {str(k): "" if v is None else str(v) for k, v in env.items()}


def _line_of(lines: list[str], service_name: str) -> int | None:
    pattern = re.compile(r"^\s+" + re.escape(service_name) + r"\s*:")
    for i, line in enumerate(lines, start=1):
        if pattern.match(line):
            return i
    return None


def _ignored(lines: list[str], line: int | None, rule_id: str) -> bool:
    """'# dave:ignore' (tout) ou '# dave:ignore DV005,DV006' sur la ligne de définition du service."""
    if not line:
        return False
    m = IGNORE_RE.search(lines[line - 1])
    if not m:
        return False
    ids = [x.strip().upper() for x in re.split(r"[,\s]+", m.group(1)) if x.strip()]
    return not ids or rule_id in ids


def audit_compose(path: Path, lang: str = "en") -> list[Finding]:
    content = path.read_text(encoding="utf-8")
    data = yaml.safe_load(content) or {}
    services = data.get("services") or {}
    lines = content.splitlines()
    findings: list[Finding] = []

    def add(rule_id, sev, name, evidence=None, **kw):
        line = _line_of(lines, name)
        if _ignored(lines, line, rule_id):
            return
        title, detail, fix = text(rule_id, lang, **kw)
        findings.append(Finding(rule_id, sev, title, detail, fix, str(path), name, line, evidence))

    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        image = svc.get("image")
        kind = identify(image)
        label = f"{name} ({kind})" if kind and kind.lower() != str(name).lower() else str(name)
        known_ports = set(default_ports(kind)) if kind else set()

        # DV001 : ports d'un service d'IA publiés sur toutes les interfaces
        for entry in svc.get("ports") or []:
            host_ip, published, target = parse_port(entry)
            is_ai_port = bool(kind) or target in SENSITIVE_PORTS
            if not is_ai_port or (host_ip and host_ip in LOCAL_HOSTS):
                continue
            if host_ip in (None, "", "0.0.0.0", "::"):
                shown = label if kind else f"{name} ({SENSITIVE_PORTS[target]})"
                add("DV001", "high", name, evidence=str(entry), service=shown,
                    port=published or "random", target=target or "?")

        # DV002 : socket Docker monté
        for vol in svc.get("volumes") or []:
            src = vol.get("source", "") if isinstance(vol, dict) else str(vol).split(":")[0]
            if "docker.sock" in str(src):
                add("DV002", "critical", name, evidence=str(vol), service=label)

        if svc.get("privileged") is True:
            add("DV003", "high", name, evidence="privileged: true", service=label)

        if str(svc.get("network_mode", "")).lower() == "host":
            add("DV004", "medium", name, evidence="network_mode: host", service=label)

        # DV005 : uniquement pour les images dont on sait qu'elles tournent en root par défaut
        if kind in ROOT_BY_DEFAULT:
            user = str(svc.get("user", "")).strip()
            if user in ("", "0", "root", "0:0", "root:root"):
                add("DV005", "medium", name, evidence=f"user: {user or '(absent)'}", service=label)

        if image and (":" not in image.split("/")[-1] or image.endswith(":latest")):
            if "@sha256:" not in image:
                add("DV006", "low", name, evidence=f"image: {image}", service=label, image=image)

        env = _env(svc)
        if kind == "Open WebUI" and env.get("WEBUI_AUTH", "").strip().strip("'\"").lower() in ("false", "0", "no"):
            add("DV007", "high", name, evidence="WEBUI_AUTH=False", service=label)
        if env.get("OLLAMA_ORIGINS", "").strip().strip("'\"") == "*":
            add("DV008", "medium", name, evidence="OLLAMA_ORIGINS=*", service=label)
        for key, val in env.items():
            val = val.strip().strip("'\"")
            if SECRET_KEY_RE.search(key) and val and not INTERPOLATION_RE.match(val):
                add("DV009", "medium", name, evidence=f"{key}=****", service=label, key=key)

        if kind == "Qdrant" and not env.get("QDRANT__SERVICE__API_KEY", "").strip():
            add("DV010", "high", name, evidence="QDRANT__SERVICE__API_KEY: (absent)", service=label)

        if kind and image and ":" in image.split("/")[-1]:
            tag = image.split("/")[-1].split(":", 1)[1].split("@")[0]
            for adv in matching(kind, tag):
                add("DV011", "critical", name, evidence=f"image: {image}", service=label,
                    product=kind, version=tag, cve=adv["id"], fixed=adv["fixed"])

    return findings


def known_service_names() -> list[str]:
    return list(AI_SERVICES)


def public_ports(path: Path) -> list[str]:
    """Ports publiés sur toutes les interfaces, pour tous les services (utile pour DV014)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for name, svc in (data.get("services") or {}).items():
        if not isinstance(svc, dict) or str(svc.get("network_mode", "")).lower() == "host":
            continue
        for entry in svc.get("ports") or []:
            host_ip, published, target = parse_port(entry)
            if host_ip in (None, "", "0.0.0.0", "::"):
                out.append(f"{name}:{published or target}")
    return out
