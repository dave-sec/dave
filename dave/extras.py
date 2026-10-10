"""Rapport HTML, badge SVG et comparaison avec un scan précédent."""
from __future__ import annotations

import html
import json
from pathlib import Path

from . import __version__
from .findings import Finding
from .report import score, sort_findings

GRADE_COLORS = {"A": "#2e8540", "B": "#7aa63a", "C": "#c9a227", "D": "#d9822b", "F": "#c0392b"}
SEV_COLORS = {"critical": "#7d1f6b", "high": "#c0392b", "medium": "#b7791f", "low": "#2b6cb0", "info": "#6b7280"}
LABELS = {
    "en": {"title": "Dave security report", "grade": "Grade", "none": "No issues found.", "fix": "Fix",
           "where": "Where", "new": "New since baseline", "fixed": "Fixed since baseline", "ai": "AI explanation"},
    "fr": {"title": "Rapport de sécurité Dave", "grade": "Note", "none": "Aucun problème détecté.", "fix": "Correctif",
           "where": "Où", "new": "Nouveaux depuis la référence", "fixed": "Corrigés depuis la référence", "ai": "Explication IA"},
}


def fingerprint(f: dict) -> str:
    return "|".join(str(f.get(k, "")) for k in ("rule_id", "source", "service", "evidence"))


def compare(findings: list[Finding], baseline_path: Path) -> dict:
    old = json.loads(baseline_path.read_text(encoding="utf-8")).get("findings", [])
    old_fp = {fingerprint(f) for f in old}
    new_fp = {fingerprint(f.to_dict()) for f in findings}
    return {
        "new": [f.to_dict() for f in findings if fingerprint(f.to_dict()) not in old_fp],
        "fixed": [f for f in old if fingerprint(f) not in new_fp],
    }


def badge_svg(findings: list[Finding]) -> str:
    _, grade = score(findings)
    color = GRADE_COLORS[grade]
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="78" height="20" role="img" aria-label="dave: ' + grade + '">'
        '<title>dave: ' + grade + '</title>'
        '<rect width="44" height="20" fill="#555"/><rect x="44" width="34" height="20" fill="' + color + '"/>'
        '<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
        '<text x="22" y="14">dave</text><text x="61" y="14">' + grade + '</text></g></svg>\n'
    )


def render_html(findings: list[Finding], lang: str = "en", diff: dict | None = None) -> str:
    lab = LABELS.get(lang, LABELS["en"])
    e = html.escape
    value, grade = score(findings)
    rows = []
    for f in sort_findings(findings):
        where = f.source + (f":{f.line}" if f.line else "") + (f" [{f.service}]" if f.service else "")
        parts = [
            f'<article class="f"><p class="sev" style="color:{SEV_COLORS[f.severity]}">{e(f.severity.upper())} &middot; {e(f.rule_id)}</p>',
            f"<h2>{e(f.title)}</h2>",
            f'<p class="where">{e(lab["where"])}: <code>{e(where)}</code></p>',
            f"<p>{e(f.detail)}</p>",
        ]
        if f.evidence:
            parts.append(f"<pre>{e(f.evidence)}</pre>")
        parts.append(f'<p><strong>{e(lab["fix"])}:</strong> {e(f.fix)}</p>')
        if f.ai_explanation:
            parts.append(f'<p><strong>{e(lab["ai"])}:</strong> {e(f.ai_explanation)}</p>')
        rows.append("".join(parts) + "</article>")
    diff_html = ""
    if diff is not None:
        diff_html = (f'<p class="diff">{e(lab["new"])}: <strong>{len(diff["new"])}</strong> &middot; '
                     f'{e(lab["fixed"])}: <strong>{len(diff["fixed"])}</strong></p>')
    body = "".join(rows) or f"<p>{e(lab['none'])}</p>"
    return f"""<!doctype html>
<html lang="{e(lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(lab['title'])}</title>
<style>
body{{margin:0;background:#f4f5f7;color:#1d2433;font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:52rem;margin:0 auto;padding:2.5rem 1.25rem}}
header{{display:flex;align-items:center;gap:1.25rem;border-bottom:2px solid #1d2433;padding-bottom:1rem;margin-bottom:1.5rem}}
.grade{{font-size:2.6rem;font-weight:800;color:#fff;background:{GRADE_COLORS[grade]};border-radius:10px;width:4.2rem;height:4.2rem;display:grid;place-items:center}}
h1{{margin:0;font-size:1.5rem}} .meta{{margin:.2rem 0 0;color:#5b6475}}
.f{{background:#fff;border:1px solid #d8dce3;border-radius:10px;padding:1rem 1.2rem;margin:0 0 1rem}}
.f h2{{font-size:1.1rem;margin:.1rem 0 .4rem}} .sev{{margin:0;font-weight:700;font-size:.85rem}}
.where{{color:#5b6475;font-size:.92rem}} code,pre{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.88rem}}
pre{{background:#f4f5f7;padding:.6rem .8rem;border-radius:6px;overflow-x:auto;white-space:pre-wrap}}
.diff{{background:#fff;border:1px solid #d8dce3;border-radius:10px;padding:.8rem 1.2rem}}
</style></head><body><main>
<header><div class="grade" aria-label="{e(lab['grade'])} {grade}">{grade}</div>
<div><h1>{e(lab['title'])}</h1><p class="meta">{e(lab['grade'])}: {grade} ({value}/100) &middot; dave {__version__}</p></div></header>
{diff_html}{body}
</main></body></html>
"""
