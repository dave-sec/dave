"""Rendu des constats : texte, JSON, SARIF 2.1.0."""
from __future__ import annotations

import json
import os
import sys

from . import __version__
from .findings import Finding, sev_rank
from .rules import RULES

COLORS = {"critical": "\033[1;35m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"
LABELS = {
    "en": {"none": "No issues found.", "summary": "Summary", "fix": "Fix", "ai": "AI explanation", "where": "Where", "grade": "Grade"},
    "fr": {"none": "Aucun problème détecté.", "summary": "Bilan", "fix": "Correctif", "ai": "Explication IA", "where": "Où", "grade": "Note"},
}


def _use_color(stream) -> bool:
    return stream.isatty() and os.environ.get("NO_COLOR") is None


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-sev_rank(f.severity), f.source, f.service or ""))


def render_text(findings: list[Finding], lang: str = "en", stream=sys.stdout) -> str:
    lab = LABELS.get(lang, LABELS["en"])
    color = _use_color(stream)
    out = []
    if not findings:
        return lab["none"] + " " + lab["grade"] + ": A (100/100)\n"
    for f in sort_findings(findings):
        sev = f.severity.upper()
        tag = f"{COLORS[f.severity]}{sev}{RESET}" if color else sev
        where = f.source + (f":{f.line}" if f.line else "") + (f" [{f.service}]" if f.service else "")
        out.append(f"[{tag}] {f.rule_id} {f.title}")
        out.append(f"  {lab['where']}: {where}")
        out.append(f"  {f.detail}")
        if f.evidence:
            out.append(f"  > {f.evidence}")
        out.append(f"  {lab['fix']}: {f.fix}")
        if f.ai_explanation:
            out.append(f"  {lab['ai']}: {f.ai_explanation}")
        out.append("")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low", "info")}
    out.append(lab["summary"] + ": " + ", ".join(f"{k} {v}" for k, v in counts.items() if v))
    value, grade = score(findings)
    out.append(f"{lab['grade']}: {grade} ({value}/100)")
    return "\n".join(out) + "\n"


WEIGHTS = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}


def score(findings: list[Finding]) -> tuple[int, str]:
    value = max(0, 100 - sum(WEIGHTS[f.severity] for f in findings))
    for limit, grade in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if value >= limit:
            return value, grade
    return value, "F"


def render_json(findings: list[Finding]) -> str:
    return json.dumps(
        {"tool": "dave", "version": __version__, "score": score(findings)[0], "grade": score(findings)[1],
         "findings": [f.to_dict() for f in sort_findings(findings)]},
        ensure_ascii=False, indent=2,
    )


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def render_sarif(findings: list[Finding]) -> str:
    used = sorted({f.rule_id for f in findings})
    rules = [
        {
            "id": rid,
            "name": RULES[rid]["en"]["title"],
            "shortDescription": {"text": RULES[rid]["en"]["title"]},
            "defaultConfiguration": {"level": _SARIF_LEVEL[RULES[rid]["severity"]]},
        }
        for rid in used
    ]
    results = []
    for f in sort_findings(findings):
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.source.replace(os.sep, "/")}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.detail} Fix: {f.fix}"},
            "locations": [loc],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "dave", "version": __version__,
                                "informationUri": "https://github.com/dave-sec/dave", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
