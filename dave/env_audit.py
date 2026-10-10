"""Pare-feu contourné par Docker (DV014) et fichiers .env non protégés de Git (DV018)."""
from __future__ import annotations

import fnmatch
import re
import shutil
import subprocess
from pathlib import Path

from .compose_audit import public_ports
from .findings import Finding
from .rules import text

UFW_CONF = Path("/etc/ufw/ufw.conf")


def ufw_enabled(conf: Path = UFW_CONF) -> bool:
    try:
        return bool(re.search(r"^\s*ENABLED\s*=\s*yes\s*$", conf.read_text(), re.M | re.I))
    except OSError:
        return False


def audit_firewall(compose_files: list[Path], lang: str = "en", conf: Path = UFW_CONF) -> list[Finding]:
    if not ufw_enabled(conf):
        return []
    findings = []
    for path in compose_files:
        ports = public_ports(path)
        if ports:
            shown = ", ".join(ports[:8]) + (" ..." if len(ports) > 8 else "")
            title, detail, fix = text("DV014", lang, source=str(path), ports=shown)
            findings.append(Finding("DV014", "high", title, detail, fix, str(path), evidence=f"UFW ENABLED=yes; {shown}"))
    return findings


def _git(repo: Path, *args: str) -> int | None:
    if not shutil.which("git"):
        return None
    try:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=10).returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def _gitignore_matches(repo: Path, rel: str) -> bool:
    gi = repo / ".gitignore"
    if not gi.is_file():
        return False
    name = rel.split("/")[-1]
    for raw in gi.read_text(errors="replace").splitlines():
        pat = raw.strip()
        if not pat or pat.startswith("#") or pat.startswith("!"):
            continue
        pat = pat.lstrip("/").rstrip("/").removeprefix("**/")
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat):
            return True
    return False


def audit_env_files(root: Path, lang: str = "en") -> list[Finding]:
    repo = root.resolve()
    if not (repo / ".git").exists():
        return []
    findings = []
    from .walk import walk_files
    for env in walk_files(repo):
        if not env.name.startswith(".env") or not env.is_file():
            continue
        if env.name.endswith((".example", ".sample", ".template", ".dist")):
            continue
        rel = env.relative_to(repo).as_posix()
        tracked = _git(repo, "ls-files", "--error-unmatch", rel) == 0
        if tracked:
            state = {"en": "committed in Git", "fr": "commité dans Git"}[lang]
            sev = "high"
        else:
            ignored = _git(repo, "check-ignore", "-q", rel)
            if ignored == 0 or (ignored is None and _gitignore_matches(repo, rel)):
                continue
            state = {"en": "not listed in .gitignore", "fr": "absent du .gitignore"}[lang]
            sev = "medium"
        title, detail, fix = text("DV018", lang, source=rel, state=state)
        findings.append(Finding("DV018", sev, title, detail, fix, str(env), evidence=state))
    return findings
