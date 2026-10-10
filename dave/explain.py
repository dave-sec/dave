"""Explications optionnelles par un modèle local (Ollama). Rien ne sort de la machine.

Les données envoyées au modèle sont limitées au constat (titre, détail, preuve masquée) :
jamais le contenu complet des fichiers ni les valeurs de secrets.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .findings import Finding

PROMPTS = {
    "en": (
        "You are a security assistant for self-hosted AI stacks. In 4 short sentences, "
        "explain to a homelab user why this finding matters and give the exact configuration change. "
        "Do not invent facts beyond the finding.\n\nFinding: {title}\nDetails: {detail}\nEvidence: {evidence}\nSuggested fix: {fix}"
    ),
    "fr": (
        "Tu es un assistant sécurité pour les stacks d'IA auto-hébergées. En 4 phrases courtes, "
        "explique à un utilisateur de homelab pourquoi ce constat est important et donne la modification "
        "de configuration exacte. N'invente rien au-delà du constat.\n\nConstat : {title}\nDétails : {detail}\n"
        "Preuve : {evidence}\nCorrectif suggéré : {fix}"
    ),
}


class ExplainError(Exception):
    pass


def explain(findings: list[Finding], url: str, model: str, lang: str = "en", timeout: float = 120.0) -> None:
    endpoint = url.rstrip("/") + "/api/generate"
    for f in findings:
        prompt = PROMPTS.get(lang, PROMPTS["en"]).format(
            title=f.title, detail=f.detail, evidence=f.evidence or "-", fix=f.fix
        )
        body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(endpoint, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ExplainError(f"Ollama unreachable at {url}: {exc}") from exc
        f.ai_explanation = str(data.get("response", "")).strip() or None
