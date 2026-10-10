# Changelog

## 0.4.0
- Update notifications: notice in the terminal, `dave update-check`, one Discord message per new version from the nightly scan.
  No auto-update, one GitHub API request per day at most, opt-out with `DAVE_NO_UPDATE_CHECK=1`.
- Releases ship a SHA256SUMS file.

## 0.3.1
- Runs on Python 3.9+ and PyYAML 5.1+: Debian 11, 12, 13 and Ubuntu 22.04+.
- `.deb` package, universal `install.sh` (native or Docker), transparent Docker wrapper, systemd timer with `/etc/default/dave`.
- Multi-arch image (amd64, arm64) published to GHCR on each release; CI on Python 3.9 to 3.13 and Debian 11, 12, 13.
- `dave scan` accepts several directories.

## 0.3.0
- New checks: Docker bypassing UFW (DV014), MCP client configs: clear-text secrets (DV015) and filesystem server on / or home (DV016),
  Nginx/Caddy exposing Ollama or Qdrant without auth (DV017), .env files not ignored or committed (DV018).
- Bounded directory walk (depth 4, media libraries skipped): fast on servers hosting photos or videos.
- Auto-fix for long port syntax (CasaOS), `--json-out`, Dockerfile.
- HTML report, SVG grade badge, comparison with a baseline report, interactive fixes (`dave fix -i`).

## 0.2.0
- OpenClaw: gateway port 18789 exposure in compose files (DV001, auto-fix), `gateway.bind` beyond loopback in
  openclaw.json, JSON5 supported (DV013), optional raw output of `openclaw security audit` (DV105).
- `dave mcp`: read-only MCP server for AI agents, with root-directory and host allowlists.

## 0.1.0
- First release: compose, host and live-probe checks, `dave fix`, A-F grade, SARIF, GitHub Action, pre-commit hook,
  English and French.
