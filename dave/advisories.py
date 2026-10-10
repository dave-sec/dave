"""Base embarquée d'avis de sécurité, uniquement des entrées sourcées.

Chaque entrée : produit, versions corrigées (toutes les versions < fixed sont vulnérables),
identifiant et lien public. Mettre à jour avec la source à chaque ajout.
"""
from __future__ import annotations

import re

ADVISORIES = [
    {
        "product": "Ollama",
        "id": "CVE-2024-37032",
        "fixed": "0.1.34",
        "url": "https://osv.dev/vulnerability/CVE-2024-37032",
    },
]

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(raw: str | None) -> tuple[int, int, int] | None:
    if not raw:
        return None
    m = _VERSION_RE.match(raw.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def matching(product: str, version: str | None) -> list[dict]:
    v = parse_version(version)
    if v is None:
        return []
    return [a for a in ADVISORIES if a["product"] == product and v < parse_version(a["fixed"])]
