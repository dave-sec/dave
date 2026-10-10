"""Vérification des nouvelles versions de Dave (GitHub Releases).

- Lecture seule : une requête GET vers l'API publique de GitHub, au plus une fois par 24 h (cache).
- Jamais de mise à jour automatique : un outil de sécurité qui se remplace seul depuis internet
  serait lui-même un risque de chaîne d'approvisionnement. Dave prévient, l'utilisateur décide.
- Désactivable : DAVE_NO_UPDATE_CHECK=1 ou --no-update-check. Désactivé en CI et en mode MCP.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.request
from pathlib import Path

from . import __repo__, __version__

API = os.environ.get("DAVE_UPDATE_API", "https://api.github.com")
REPO = os.environ.get("DAVE_UPDATE_REPO", __repo__)
CHECK_EVERY = 24 * 3600
VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def cache_file() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "dave" / "update.json"


def disabled() -> bool:
    return bool(os.environ.get("DAVE_NO_UPDATE_CHECK") or os.environ.get("CI")) or REPO.startswith("OWNER/")


def parse(v: str | None) -> tuple[int, int, int] | None:
    m = VERSION_RE.match((v or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def is_newer(latest: str | None, current: str = __version__) -> bool:
    a, b = parse(latest), parse(current)
    return bool(a and b and a > b)


def fetch_latest(timeout: float = 2.0) -> str | None:
    """Dernière version publiée (hors brouillons et pré-versions), ou None."""
    req = urllib.request.Request(
        f"{API}/repos/{REPO}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": f"dave/{__version__}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(200_000).decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None
    tag = str(data.get("tag_name", "")) if isinstance(data, dict) else ""
    return tag.lstrip("v") if parse(tag) else None


def latest(force: bool = False, now: float | None = None) -> str | None:
    now = now or time.time()
    path = cache_file()
    try:
        cached = json.loads(path.read_text())
        if not force and now - cached.get("checked_at", 0) < CHECK_EVERY:
            return cached.get("latest")
    except (OSError, ValueError):
        pass
    version = fetch_latest()
    try:  # on mémorise aussi les échecs, pour ne pas réessayer à chaque commande
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"checked_at": now, "latest": version}))
    except OSError:
        pass
    return version


def install_method() -> str:
    forced = os.environ.get("DAVE_INSTALL_METHOD")
    if forced:
        return forced
    here = str(Path(__file__).resolve())
    if here.startswith("/usr/lib/python3/dist-packages/"):
        return "deb"
    if "/pipx/" in here:
        return "pipx"
    return "pip"


def upgrade_hint(version: str, lang: str = "en") -> str:
    url = f"https://github.com/{REPO}/releases/tag/v{version}"
    hints = {
        "deb": f"sudo apt install ./dave_{version}_all.deb   ({url})",
        "docker": f"docker pull ghcr.io/{REPO.split('/')[0].lower()}/dave:{version}",
        "docker-wrapper": f"git pull && sudo ./install.sh --docker   ({url})",
        "pipx": "pipx upgrade dave-ai",
        "pip": "pip install -U dave-ai",
    }
    cmd = hints.get(install_method(), hints["pip"])
    if lang == "fr":
        return f"Dave {version} est disponible (vous avez {__version__}). Mise à jour : {cmd}"
    return f"Dave {version} is available (you have {__version__}). Upgrade: {cmd}"


class BackgroundCheck:
    """Vérifie en arrière-plan pendant le scan : n'ajoute aucune attente perceptible."""

    def __init__(self):
        self.result: str | None = None
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        self.result = latest()

    def notice(self, lang: str, wait: float = 0.5) -> str | None:
        self._t.join(wait)
        return upgrade_hint(self.result, lang) if is_newer(self.result) else None


def maybe_notify(check: BackgroundCheck | None, lang: str, stream=sys.stderr) -> None:
    if check is None or not stream.isatty():
        return
    msg = check.notice(lang)
    if msg:
        stream.write(f"\n{msg}\n")
