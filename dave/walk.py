"""Parcours de fichiers borné : profondeur limitée, dossiers lourds ignorés, liens symboliques non suivis.

Indispensable sur un serveur qui héberge des photos ou des vidéos : un parcours récursif complet
d'une bibliothèque Immich ou Jellyfin prendrait des minutes et solliciterait le disque pour rien.
"""
from __future__ import annotations

import os
from pathlib import Path

MAX_DEPTH = int(os.environ.get("DAVE_MAX_DEPTH", "4"))
DEFAULT_EXCLUDES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".cache", "site-packages",
    # bibliothèques multimédia (Immich, Jellyfin...) : jamais de compose dedans
    "library", "upload", "thumbs", "encoded-video", "profile", "backups", "metadata", "transcodes",
}
EXTRA_EXCLUDES: set[str] = set()


def walk_files(root: Path, max_depth: int | None = None):
    depth_limit = MAX_DEPTH if max_depth is None else max_depth
    root = Path(root)
    base = len(root.resolve().parts)
    excludes = DEFAULT_EXCLUDES | EXTRA_EXCLUDES
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = len(Path(dirpath).resolve().parts) - base
        dirnames[:] = sorted(d for d in dirnames if d not in excludes and not (depth >= depth_limit))
        for name in sorted(filenames):
            yield Path(dirpath) / name
