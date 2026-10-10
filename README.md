# Dave

**Security audit for self-hosted AI stacks.** Dave checks OpenClaw, Ollama, Open WebUI, n8n, LiteLLM, vLLM, Qdrant and
friends for the mistakes that expose them to your whole network, or to the internet, and fixes the simple ones for you.

- **100% local.** No account, no cloud API. Optional explanations come from *your own* Ollama model.
- **Config, host and network.** Reads docker-compose files, checks a systemd install of Ollama, and probes the services that are actually running.
- **Sourced rules only.** Every check links to the documentation or advisory behind it. See [docs/rules.md](docs/rules.md).
- **Usable by AI agents.** `dave mcp` exposes Dave as a read-only MCP server.
- **Built for CI.** SARIF output for GitHub Code Scanning, a GitHub Action, a pre-commit hook, and exit codes.
- **English and French.**

> Version française : [README.fr.md](README.fr.md)

## Install

Works on Debian 11, 12, 13, Ubuntu 22.04+ and any machine with Docker (amd64 and arm64). Python 3.9+.

    git clone https://github.com/dave-sec/dave && cd dave
    sudo ./install.sh            # .deb package if possible, Docker otherwise
    sudo ./install.sh --timer    # same, plus a nightly scan (systemd timer)

Other options:

    sudo apt install ./dave_<version>_all.deb          # package from the GitHub release
    docker run --rm ghcr.io/dave-sec/dave:latest --help    # published image
    pipx install git+https://github.com/dave-sec/dave      # any OS with Python 3.9+

The nightly scan is configured in `/etc/default/dave` (directories, OpenClaw, Discord webhook).
It runs a few seconds with the lowest CPU and disk priority, and is capped at 1 CPU and 128 MB in Docker mode.

## Usage

    dave scan                         # compose files in ., host install, localhost probe
    dave compose ./stack              # docker-compose files only
    dave fix ./stack                  # preview safe fixes as a diff
    dave fix ./stack --write          # apply them (a .bak copy is kept)
    dave fix ./stack -i               # review and approve each fix, then see the new grade
    dave host                         # Ollama systemd install + OpenClaw gateway config
    dave host --with-openclaw-audit   # also run OpenClaw's own 'openclaw security audit'
    dave mcp                          # MCP server for AI agents (read-only)
    dave probe --host 192.168.1.20    # a machine YOU OWN
    dave scan --explain --model llama3.2   # plain-language explanations from your local Ollama
    dave scan --format html -o report.html --badge dave.svg   # shareable report and README badge
    dave scan --format json -o today.json --baseline last-week.json  # what is new, what was fixed

Every report ends with a grade from A to F. The exit code is `1` when a finding reaches `--fail-on`
(default `high`).

## What it checks

| ID | Severity | Check |
|----|----------|-------|
| DV001 | high | AI service port published on all interfaces (auto-fix) |
| DV002 | critical | Docker socket mounted in a container |
| DV003 | high | Privileged container |
| DV004 | medium | Container on the host network |
| DV005 | medium | Ollama running as root |
| DV006 | low | Unpinned image (`latest` or no tag) |
| DV007 | high | Open WebUI authentication disabled |
| DV008 | medium | Ollama accepts any web origin (auto-fix) |
| DV009 | medium | Secret written in clear in the compose file |
| DV010 | high | Qdrant without an API key |
| DV011 | critical | Image version with a known vulnerability (e.g. CVE-2024-37032 in Ollama) |
| DV012 | high | Ollama systemd install listening on all interfaces |
| DV014 | high | UFW is enabled but Docker-published ports bypass it |
| DV015 | medium | Secret in clear in an MCP client config (Claude Desktop, Cursor, VS Code, .mcp.json) |
| DV016 | high | MCP filesystem server allowed on `/` or your home directory |
| DV017 | high | Nginx or Caddy exposes Ollama or Qdrant without authentication |
| DV018 | medium/high | `.env` file not ignored by Git (high if already committed) |
| DV013 | medium | OpenClaw gateway bound beyond loopback (`lan`, `custom`; `tailnet` is low) |
| DV101 | high | Ollama answers without authentication (live) |
| DV102 | medium | AI service port reachable (live) |
| DV103 | critical | Running Ollama version is vulnerable (live) |
| DV104 | high | Qdrant answers without authentication (live) |
| DV105 | info | Raw output of `openclaw security audit` (opt-in) |

The OpenClaw gateway port (18789) is treated like Ollama's: published on all interfaces in a compose file, it triggers DV001 and can be auto-fixed.

Live findings on `127.0.0.1` are reported as `info`: single-user local use is fine.

## Use Dave from an AI agent (MCP)

`dave mcp` runs a Model Context Protocol server over stdio. Tools: `dave_scan_compose`, `dave_fix_preview`,
`dave_host_audit`, `dave_probe`, `dave_rule`. Example configuration for an MCP client:

    {
      "mcpServers": {
        "dave": {
          "command": "dave",
          "args": ["mcp"],
          "env": {"DAVE_MCP_ROOT": "/home/me/homelab", "DAVE_MCP_ALLOWED_HOSTS": "127.0.0.1,192.168.1.20"}
        }
      }
    }

Safety by design: the server never writes files (fixes are previews only), only reads under `DAVE_MCP_ROOT`,
and only probes hosts listed in `DAVE_MCP_ALLOWED_HOSTS` (default `127.0.0.1`), so a prompt-injected agent
cannot turn it against other machines.

## Updates

Dave tells you when a new version is out, and never updates itself: a security tool that replaces its own
code from the internet would be a supply-chain risk.

- In a terminal, a one-line notice after the report (on stderr, so JSON/SARIF outputs stay clean).
- `dave update-check` checks now and prints the right upgrade command for your install (.deb, Docker, pipx).
- The nightly scan sends one Discord message per new version, never twice.
- At most one request per day to the public GitHub API, nothing else is sent. Opt out with
  `DAVE_NO_UPDATE_CHECK=1` or `--no-update-check`. Disabled in CI and in MCP mode.
- Each release ships a `SHA256SUMS` file to verify the `.deb` before installing.

## Silencing a finding

Inline, on the service line of the compose file:

    services:
      legacy:  # dave:ignore DV006

Or project-wide in `.dave.yml` (see [.dave.yml.example](.dave.yml.example)).

## GitHub Action

    - uses: dave-sec/dave@v0.4.0
      with:
        path: .
        fail-on: high

## Dave Pro

Continuous monitoring of your machines, alerts on Discord, Slack or ntfy when a new issue appears, and grade history.
Buy a license, then `pip install dave-pro && dave-pro activate <KEY>`. Dave itself stays free and open source.

## Legal

Only probe machines you own or are explicitly authorized to test. The probe opens TCP connections and sends
read-only HTTP GET requests (`/api/tags`, `/api/version`, `/collections`); it never attempts exploitation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues in Dave itself: [SECURITY.md](SECURITY.md).

## License

AGPL-3.0-or-later.
