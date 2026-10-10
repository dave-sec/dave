"""Catalogue des services d'IA auto-hébergés connus : images Docker et ports par défaut."""
from __future__ import annotations

# nom lisible -> (fragments d'image, ports conteneur par défaut)
AI_SERVICES: dict[str, tuple[tuple[str, ...], tuple[int, ...]]] = {
    "Ollama": (("ollama/ollama",), (11434,)),
    "Open WebUI": (("open-webui/open-webui",), (8080,)),
    "n8n": (("n8nio/n8n",), (5678,)),
    "LiteLLM": (("berriai/litellm",), (4000,)),
    "vLLM": (("vllm/vllm-openai",), (8000,)),
    "LocalAI": (("localai/localai", "go-skynet/local-ai"), (8080,)),
    "Langflow": (("langflowai/langflow",), (7860,)),
    "Flowise": (("flowiseai/flowise",), (3000,)),
    "AnythingLLM": (("mintplexlabs/anythingllm",), (3001,)),
    "Qdrant": (("qdrant/qdrant",), (6333, 6334)),
    "Chroma": (("chromadb/chroma",), (8000,)),
    "Text Generation Inference": (("huggingface/text-generation-inference",), (80,)),
    "Dify": (("langgenius/dify",), (5001, 80)),
    "Jupyter": (("jupyter/", "quay.io/jupyter"), (8888,)),
}

# Ports propres à un service d'IA : signalés même si l'image n'est pas reconnue.
SENSITIVE_PORTS: dict[int, str] = {11434: "Ollama", 18789: "OpenClaw"}

# Ports réseau sondés par défaut avec le service qu'on y attend.
PROBE_PORTS: dict[int, str] = {
    11434: "Ollama",
    8080: "Open WebUI / LocalAI",
    3000: "Open WebUI / Flowise",
    5678: "n8n",
    4000: "LiteLLM",
    8000: "vLLM / Chroma",
    7860: "Langflow / text-generation-webui",
    3001: "AnythingLLM",
    6333: "Qdrant",
    8888: "Jupyter",
    18789: "OpenClaw",
}


def identify(image: str | None) -> str | None:
    if not image:
        return None
    img = image.lower()
    for name, (fragments, _ports) in AI_SERVICES.items():
        if any(f in img for f in fragments):
            return name
    return None


def default_ports(name: str) -> tuple[int, ...]:
    return AI_SERVICES.get(name, ((), ()))[1]
