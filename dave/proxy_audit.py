"""Reverse proxies (Nginx, Caddy) qui publient Ollama ou Qdrant sans authentification (DV017).

Seuls Ollama et Qdrant sont visés : leur absence d'authentification par défaut est sourcée.
Les services qui ont leur propre authentification (Open WebUI, OpenClaw...) ne sont pas signalés.
"""
from __future__ import annotations

import re
from pathlib import Path

from .findings import Finding
from .rules import text

TARGETS = {"Ollama": (re.compile(r"ollama|:11434\b", re.I),), "Qdrant": (re.compile(r"qdrant|:633[34]\b", re.I),)}
NGINX_AUTH = re.compile(r"^\s*(auth_basic\s+(?!off\b)|auth_request\s)", re.M)
CADDY_AUTH = re.compile(r"^\s*(basic_?auth|forward_auth)\b", re.M | re.I)


def _blocks(raw: str, opener: re.Pattern) -> list[tuple[int, str]]:
    out = []
    for m in opener.finditer(raw):
        depth, start = 0, m.end() - 1
        for i in range(start, len(raw)):
            if raw[i] == "{":
                depth += 1
            elif raw[i] == "}":
                depth -= 1
                if depth == 0:
                    out.append((raw.count("\n", 0, m.start()) + 1, raw[start:i + 1]))
                    break
    return out


def _strip(raw: str) -> str:
    return re.sub(r"#[^\n]*", "", raw)


def _check(path: Path, blocks, proxy_re: re.Pattern, auth_re: re.Pattern, lang: str) -> list[Finding]:
    findings = []
    for line, body in blocks:
        if auth_re.search(body):
            continue
        for m in proxy_re.finditer(body):
            target = m.group(1)
            for product, (pattern,) in TARGETS.items():
                if pattern.search(target):
                    title, detail, fix = text("DV017", lang, source=str(path), product=product, target=target)
                    findings.append(Finding("DV017", "high", title, detail, fix, str(path), product, line,
                                            evidence=m.group(0).strip()))
                    break
    return findings


def audit_proxy_file(path: Path, lang: str = "en") -> list[Finding]:
    try:
        raw = _strip(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []
    if path.name.lower().startswith("caddyfile"):
        blocks = _blocks(raw, re.compile(r"^[^\s{#][^{\n]*\{", re.M))
        return _check(path, blocks, re.compile(r"reverse_proxy\s+([^\s{]+)"), CADDY_AUTH, lang)
    blocks = _blocks(raw, re.compile(r"\bserver\s*\{"))
    return _check(path, blocks, re.compile(r"proxy_pass\s+([^;\s]+)"), NGINX_AUTH, lang)


def find_proxy_files(root: Path) -> list[Path]:
    from .walk import walk_files
    out = []
    for p in walk_files(root):
        if p.name.lower().startswith("caddyfile"):
            out.append(p)
        elif p.suffix == ".conf":
            try:
                if p.stat().st_size < 1_000_000 and "proxy_pass" in p.read_text(errors="ignore"):
                    out.append(p)
            except OSError:
                continue
    return out
