# Roadmap

## Open source (free, AGPL)
- OpenClaw version advisories, once each CVE is confirmed in an official advisory (GitHub Security Advisories / OSV).
- More sourced rules: LiteLLM master key, Chroma authentication, n8n exposure.
- Agent mode on top of the MCP server: guided remediation with human approval for every change.
- Optional online advisory lookup (OSV) instead of the embedded list.
- Reverse-proxy checks (Nginx, Caddy, Traefik): missing authentication in front of AI services.
- Kubernetes manifests and Helm values.

## Dave Pro (paid, hosted)
- Continuous monitoring of several machines, with alerts (e-mail, Slack, Discord).
- History and trends of the grade.
- PDF report for small businesses deploying local AI (useful for GDPR and security reviews).
