"""dave: security audit for self-hosted AI stacks."""
from __future__ import annotations

import argparse
import json
import io
import locale
import os
import sys
from pathlib import Path

import yaml

from . import __version__
from . import config as cfgmod
from .compose_audit import audit_compose, find_compose_files
from .fixer import FIXABLE, fix_file
from .env_audit import audit_env_files, audit_firewall
from .extras import badge_svg, compare, render_html
from .fixer import interactive
from .host_audit import audit_host
from .mcp_config_audit import audit_mcp_config, config_files
from .proxy_audit import audit_proxy_file, find_proxy_files
from .openclaw_audit import audit_config, native_audit
from .explain import ExplainError, explain
from .findings import SEVERITIES, sev_rank
from .network_probe import is_loopback, probe
from .report import render_json, render_sarif, render_text, score
from . import updates

AUTHORIZED_NOTE = {
    "en": "Only scan machines you own or are explicitly authorized to test.",
    "fr": "Ne scannez que des machines qui vous appartiennent ou que vous êtes explicitement autorisé à tester.",
}


def default_lang() -> str:
    env = os.environ.get("DAVE_LANG")
    if env in ("en", "fr"):
        return env
    loc = (locale.getlocale()[0] or os.environ.get("LANG", "")).lower()
    return "fr" if loc.startswith("fr") else "en"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dave", description="Security audit for self-hosted AI stacks (Ollama, Open WebUI, n8n, LiteLLM...).")
    p.add_argument("--version", action="version", version=f"dave {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--lang", choices=["en", "fr"], default=None, help="output language (default: from locale)")
    common.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    common.add_argument("--json-out", help="also write the JSON report to this file (usable later as --baseline)")
    common.add_argument("--badge", help="also write an SVG grade badge to this file")
    common.add_argument("--baseline", help="previous JSON report: show what is new and what was fixed")
    common.add_argument("--output", "-o", help="write the report to a file")
    common.add_argument("--fail-on", choices=SEVERITIES, default="high",
                        help="exit code 1 if a finding is at least this severe (default: high)")
    common.add_argument("--explain", action="store_true", help="add explanations from a local Ollama model")
    common.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    common.add_argument("--model", default="llama3.2", help="Ollama model used by --explain")
    common.add_argument("--no-update-check", action="store_true", help="do not check for new versions")
    common.add_argument("--max-depth", type=int, default=None, help="how deep to search directories (default 4)")
    common.add_argument("--exclude", action="append", default=[], help="directory name to skip (repeatable)")
    common.add_argument("--config", help="path to a .dave.yml file (default: ./.dave.yml if present)")
    common.add_argument("--openclaw-config", help="path to openclaw.json (default: ~/.openclaw/openclaw.json)")
    common.add_argument("--with-openclaw-audit", action="store_true",
                        help="also run 'openclaw security audit' and include its raw output")

    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("compose", parents=[common], help="audit docker-compose files")
    c.add_argument("paths", nargs="+", help="compose files or directories to search")

    n = sub.add_parser("probe", parents=[common], help="probe a host for exposed AI services")
    n.add_argument("--host", default="127.0.0.1", help="target you own (default: 127.0.0.1)")

    h = sub.add_parser("host", parents=[common], help="audit a host install of Ollama (systemd)")
    h.add_argument("paths", nargs="*", help="unit files or drop-in directories (default: standard systemd paths)")

    s = sub.add_parser("scan", parents=[common], help="compose files + host install + localhost probe")
    s.add_argument("directories", nargs="*", default=["."], help="one or more directories (default: .)")

    u = sub.add_parser("update-check", parents=[common], help="check now whether a new version is available")
    u.add_argument("--plain", action="store_true", help="print only the new version number (for scripts)")

    sub.add_parser("mcp", parents=[common], help="run Dave as a read-only MCP server (stdio) for AI agents")

    f = sub.add_parser("fix", parents=[common], help="show (or apply with --write) safe fixes for compose files")
    f.add_argument("paths", nargs="+")
    f.add_argument("--write", action="store_true", help="apply the fixes (a .bak copy is kept)")
    f.add_argument("--interactive", "-i", action="store_true", help="review and approve each fix one by one")
    return p


def _collect_compose(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(find_compose_files(path))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(raw)
    return files


def _run_fix(args, lang: str, cfg: dict) -> int:
    if args.interactive:
        total = 0
        for path in _collect_compose(args.paths):
            before = audit_compose(path, lang)
            total += interactive(path, cfgmod.apply(before, cfg))
            grade_before, grade_after = score(before)[1], score(audit_compose(path, lang))[1]
            print(f"{path}: {grade_before} -> {grade_after}")
        print(f"{total} fix(es) applied." if lang == "en" else f"{total} correctif(s) appliqué(s).")
        return 0
    any_diff = False
    for path in _collect_compose(args.paths):
        found = [f for f in cfgmod.apply(audit_compose(path, lang), cfg) if f.rule_id in FIXABLE]
        diff = fix_file(path, found, write=args.write)
        if diff:
            any_diff = True
            print(diff)
    if not any_diff:
        print("Nothing to fix automatically." if lang == "en" else "Rien à corriger automatiquement.")
    elif args.write:
        print("Fixes applied, backups saved as *.bak." if lang == "en" else "Correctifs appliqués, sauvegardes en *.bak.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    lang = args.lang or default_lang()
    from . import walk
    if args.max_depth is not None:
        walk.MAX_DEPTH = args.max_depth
    walk.EXTRA_EXCLUDES.update(args.exclude)
    if args.command == "update-check":
        return _run_update_check(args, lang)
    check = None
    if args.command != "mcp" and not args.no_update_check and not updates.disabled():
        check = updates.BackgroundCheck()
    try:
        return _main(args, lang)
    finally:
        updates.maybe_notify(check, lang)


def _run_update_check(args, lang: str) -> int:
    """Codes de sortie : 0 à jour, 10 nouvelle version, 3 vérification impossible."""
    if updates.REPO.startswith("OWNER/"):
        print("dave: update repository not configured (__repo__)", file=sys.stderr)
        return 3
    version = updates.latest(force=True)
    if version is None:
        print("Could not check for updates." if lang == "en" else "Vérification impossible pour le moment.", file=sys.stderr)
        return 3
    if updates.is_newer(version):
        print(version if args.plain else updates.upgrade_hint(version, lang))
        return 10
    if not args.plain:
        print(f"Dave {__version__}: up to date." if lang == "en" else f"Dave {__version__} est à jour.")
    return 0


def _main(args, lang: str) -> int:
    findings = []
    try:
        cfg = cfgmod.load(Path(args.config) if args.config else None)
        if args.command == "mcp":
            from .mcp_server import Server
            Server().serve()
            return 0
        if args.command == "fix":
            return _run_fix(args, lang, cfg)
        if args.command in ("compose", "scan"):
            paths = args.paths if args.command == "compose" else args.directories
            compose_files = _collect_compose(paths)
            for f in compose_files:
                findings.extend(audit_compose(f, lang))
            findings.extend(audit_firewall(compose_files, lang))
        if args.command == "scan":
            for root in map(Path, args.directories):
                findings.extend(audit_env_files(root, lang))
                for pf in find_proxy_files(root):
                    findings.extend(audit_proxy_file(pf, lang))
        if args.command in ("host", "scan"):
            paths = [Path(x) for x in getattr(args, "paths", None) or []] if args.command == "host" else []
            findings.extend(audit_host(paths or None, lang))
            oc = Path(args.openclaw_config) if args.openclaw_config else None
            findings.extend(audit_config(oc, lang))
            if args.with_openclaw_audit:
                findings.extend(native_audit(lang))
            projects = [Path(d) for d in args.directories] if args.command == "scan" else [None]
            seen = set()
            for project in projects:
                for mc in config_files(project):
                    if mc.resolve() not in seen:
                        seen.add(mc.resolve())
                        findings.extend(audit_mcp_config(mc, lang))
        if args.command in ("probe", "scan"):
            host = getattr(args, "host", "127.0.0.1")
            if not is_loopback(host):
                print(AUTHORIZED_NOTE[lang], file=sys.stderr)
            findings.extend(probe(host, lang=lang))
    except FileNotFoundError as exc:
        print(f"dave: file not found: {exc}", file=sys.stderr)
        return 2
    except yaml.YAMLError as exc:
        print(f"dave: invalid YAML: {exc}", file=sys.stderr)
        return 2
    findings = cfgmod.apply(findings, cfg)

    if args.explain and findings:
        try:
            explain(findings, args.ollama_url, args.model, lang)
        except ExplainError as exc:
            print(f"dave: {exc}", file=sys.stderr)

    diff = compare(findings, Path(args.baseline)) if args.baseline else None
    if args.badge:
        Path(args.badge).write_text(badge_svg(findings), encoding="utf-8")
    if args.json_out:
        data = json.loads(render_json(findings))
        if diff is not None:
            data["baseline"] = {"new": len(diff["new"]), "fixed": len(diff["fixed"])}
        Path(args.json_out).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.format == "json":
        out = render_json(findings)
        if diff is not None:
            data = json.loads(out)
            data["baseline"] = {"new": len(diff["new"]), "fixed": len(diff["fixed"])}
            out = json.dumps(data, ensure_ascii=False, indent=2)
    elif args.format == "html":
        out = render_html(findings, lang, diff)
    elif args.format == "sarif":
        out = render_sarif(findings)
    else:
        out = render_text(findings, lang, stream=io.StringIO() if args.output else sys.stdout)
        if diff is not None:
            label = ("New", "fixed") if lang == "en" else ("Nouveaux", "corrigés")
            out += f"{label[0]}: {len(diff['new'])}, {label[1]}: {len(diff['fixed'])}\n"

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out if out.endswith("\n") else out + "\n")

    threshold = sev_rank(args.fail_on)
    return 1 if any(sev_rank(f.severity) >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
