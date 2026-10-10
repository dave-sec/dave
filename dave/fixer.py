"""Correctifs automatiques sûrs, proposés sous forme de diff (rien n'est écrit sans --write).

Pris en charge :
- DV001 : '11434:11434' -> '127.0.0.1:11434:11434' (syntaxe courte des ports).
- DV008 : la ligne OLLAMA_ORIGINS=* est commentée.
"""
from __future__ import annotations

import ast
import difflib
import re
import shutil
from pathlib import Path

from .findings import Finding

FIXABLE = {"DV001", "DV008"}


def _service_block(lines: list[str], start: int) -> range:
    """Indices (0-based) des lignes du service dont la définition est à la ligne `start` (1-based)."""
    indent = len(lines[start - 1]) - len(lines[start - 1].lstrip())
    end = len(lines)
    for i in range(start, len(lines)):
        stripped = lines[i].strip()
        if stripped and not stripped.startswith("#"):
            cur = len(lines[i]) - len(lines[i].lstrip())
            if cur <= indent:
                end = i
                break
    return range(start, end)


def _fix_long_port(new: list[str], block: range, entry: dict) -> None:
    """Syntaxe longue (CasaOS) : ajoute 'host_ip: 127.0.0.1' sous l'entrée '- target: X'."""
    target = entry.get("target")
    for i in block:
        m = re.match(r"^(\s*)-\s*target:\s*['\"]?%s['\"]?\s*$" % re.escape(str(target)), new[i])
        if not m:
            continue
        key_indent = len(m.group(1)) + 2
        j = i + 1
        while j < len(new) and new[j].strip() and len(new[j]) - len(new[j].lstrip()) >= key_indent \
                and not new[j].lstrip().startswith("- "):
            if new[j].strip().startswith("host_ip:"):
                return
            j += 1
        new.insert(i + 1, " " * key_indent + "host_ip: 127.0.0.1")
        return


def patch_lines(lines: list[str], findings: list[Finding]) -> list[str]:
    new = list(lines)
    # du bas vers le haut : une ligne insérée ne décale pas les constats suivants
    for f in sorted(findings, key=lambda x: x.line or 0, reverse=True):
        if f.rule_id not in FIXABLE or not f.line:
            continue
        block = _service_block(new, f.line)
        if f.rule_id == "DV001" and f.evidence and f.evidence.startswith("{"):
            try:
                _fix_long_port(new, block, ast.literal_eval(f.evidence))
            except (ValueError, SyntaxError):
                pass
        elif f.rule_id == "DV001" and f.evidence and ":" in f.evidence:
            entry = f.evidence
            pat = re.compile(r"""^(\s*-\s*)(["']?)""" + re.escape(entry) + r"""(["']?)(\s*(#.*)?)$""")
            for i in block:
                m = pat.match(new[i])
                if m:
                    new[i] = f"{m.group(1)}{m.group(2)}127.0.0.1:{entry}{m.group(3)}{m.group(4)}"
                    break
        elif f.rule_id == "DV008":
            for i in block:
                if re.search(r"""OLLAMA_ORIGINS\s*[=:]\s*["']?\*""", new[i]) and not new[i].lstrip().startswith("#"):
                    indent = new[i][: len(new[i]) - len(new[i].lstrip())]
                    new[i] = f"{indent}# {new[i].lstrip()}  # disabled by dave: wildcard origin"
                    break
    return new


def fix_file(path: Path, findings: list[Finding], write: bool = False) -> str:
    original = path.read_text(encoding="utf-8").splitlines(keepends=False)
    mine = [f for f in findings if f.source == str(path)]
    patched = patch_lines(original, mine)
    diff = "\n".join(difflib.unified_diff(original, patched, f"a/{path}", f"b/{path}", lineterm=""))
    if write and patched != original:
        shutil.copyfile(path, str(path) + ".bak")
        path.write_text("\n".join(patched) + "\n", encoding="utf-8")
    return diff


def interactive(path: Path, findings: list[Finding], ask=input, out=print) -> int:
    """Propose chaque correctif un par un ; n'applique que ceux acceptés. Renvoie le nombre appliqué."""
    original = path.read_text(encoding="utf-8").splitlines()
    current = list(original)
    applied = 0
    todo = [f for f in findings if f.rule_id in FIXABLE and f.source == str(path)]
    for f in sorted(todo, key=lambda x: x.line or 0, reverse=True):
        candidate = patch_lines(current, [f])
        if candidate == current:
            continue
        out(f"\n{f.rule_id} {f.title} [{f.service}]")
        out("\n".join(difflib.unified_diff(current, candidate, lineterm="", n=1)))
        if ask("Apply? / Appliquer ? [y/N] ").strip().lower() in ("y", "yes", "o", "oui"):
            current = candidate
            applied += 1
    if applied:
        shutil.copyfile(path, str(path) + ".bak")
        path.write_text("\n".join(current) + "\n", encoding="utf-8")
    return applied
