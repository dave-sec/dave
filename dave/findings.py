from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    fix: str
    source: str  # fichier compose ou cible réseau
    service: str | None = None
    line: int | None = None
    evidence: str | None = None
    ai_explanation: str | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, {}, "")}
