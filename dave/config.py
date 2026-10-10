"""Configuration optionnelle .dave.yml : exclusions de règles.

Exemple :
    ignore:
      - DV006                 # règle ignorée partout
    ignore_services:
      DV005: [ollama]         # règle ignorée pour ces services seulement
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .findings import Finding


def load(path: Path | None) -> dict:
    if path is None:
        default = Path(".dave.yml")
        path = default if default.is_file() else None
    if path is None:
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def apply(findings: list[Finding], cfg: dict) -> list[Finding]:
    ignore = {str(r).upper() for r in cfg.get("ignore") or []}
    per_service = {str(k).upper(): {str(s) for s in v or []} for k, v in (cfg.get("ignore_services") or {}).items()}
    kept = []
    for f in findings:
        if f.rule_id in ignore:
            continue
        if f.service and f.service in per_service.get(f.rule_id, set()):
            continue
        kept.append(f)
    return kept
