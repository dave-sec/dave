# Rules

Every rule is backed by a public reference. Severity is the default; live-probe findings on 127.0.0.1 are downgraded to `info`.

## DV001: AI service published on all network interfaces

- Severity: **high**  
- Auto-fix: `dave fix`
- Fix: Bind the port to localhost ('127.0.0.1:<port>:<target>') and put an authenticating reverse proxy in front if remote access is needed.
- References: <https://dev.to/techiemike/self-hosted-ai-security-what-every-ollama-user-should-know-29ie>, <https://docs.docker.com/engine/network/packet-filtering-firewalls/>

## DV002: Docker socket mounted into a container

- Severity: **critical**
- Fix: Remove the docker.sock volume. If the feature is required, use a filtering socket proxy that only allows the needed API calls.
- References: <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>

## DV003: Privileged container

- Severity: **high**
- Fix: Remove privileged: true and grant only the specific devices or capabilities needed (for GPUs, use the 'deploy.resources.reservations.devices' syntax).
- References: <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>

## DV004: Container shares the host network

- Severity: **medium**
- Fix: Use a dedicated Docker network and publish only the ports you need, bound to 127.0.0.1.
- References: <https://docs.docker.com/engine/network/drivers/host/>

## DV005: AI service runs as root

- Severity: **medium**
- Fix: Add a non-root 'user:' (for example "1000:1000") if the image supports it, and fix volume ownership accordingly.
- References: <https://dev.to/techiemike/self-hosted-ai-security-what-every-ollama-user-should-know-29ie>, <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>

## DV006: Unpinned image version

- Severity: **low**
- Fix: Pin an explicit version tag (or digest) and update it deliberately.
- References: <https://docs.docker.com/build/building/best-practices/>

## DV007: Open WebUI authentication disabled

- Severity: **high**
- Fix: Remove WEBUI_AUTH=False (authentication is on by default) and create user accounts.
- References: <https://docs.openwebui.com/getting-started/env-configuration>

## DV008: Ollama accepts requests from any web origin

- Severity: **medium**  
- Auto-fix: `dave fix`
- Fix: List only the origins you use, for example OLLAMA_ORIGINS=http://localhost:3000.
- References: <https://github.com/ollama/ollama/blob/main/docs/faq.md>

## DV009: Secret written in clear in the compose file

- Severity: **medium**
- Fix: Move the value to a .env file excluded from Git (or Docker secrets) and reference it as $<<<key>>>.
- References: <https://docs.docker.com/compose/how-tos/use-secrets/>

## DV010: Qdrant runs without an API key

- Severity: **high**
- Fix: Set QDRANT__SERVICE__API_KEY from a secret (for example $<<QDRANT_API_KEY>> in a .env file) and pass the key in your clients.
- References: <https://qdrant.tech/documentation/guides/security>

## DV011: Known vulnerable <product> version

- Severity: **critical**
- Fix: Upgrade to <fixed> or later, ideally the latest release, and pin that version.
- References: <https://osv.dev/vulnerability/CVE-2024-37032>

## DV012: Ollama configured to listen on all interfaces

- Severity: **high**
- Fix: Remove the override or set OLLAMA_HOST=127.0.0.1, then 'systemctl daemon-reload && systemctl restart ollama'. Use an authenticating reverse proxy for remote access.
- References: <https://github.com/ollama/ollama/blob/main/docs/faq.md>

## DV013: OpenClaw gateway listens beyond loopback

- Severity: **medium**
- Fix: Set gateway.bind to 'loopback' and reach the gateway through an SSH tunnel or Tailscale Serve. If you must bind to the LAN, firewall port <port> to a tight source-IP allowlist and keep gateway auth enabled.
- References: <https://docs.openclaw.ai/gateway/security/network-exposure.md>

## DV014: Docker bypasses your UFW firewall

- Severity: **high**
- Fix: Bind published ports to 127.0.0.1 (see DV001 and 'dave fix'), or filter Docker traffic in the DOCKER-USER chain. Do not rely on UFW alone for containers.
- References: <https://docs.docker.com/engine/network/packet-filtering-firewalls/>

## DV015: Secret in clear in an MCP client configuration

- Severity: **medium**
- Fix: Reference the secret from the environment or a secret manager instead of writing it in the file, and restrict the file permissions (chmod 600).
- References: <https://docs.docker.com/compose/how-tos/use-secrets/>

## DV016: MCP filesystem server can reach the whole disk or home

- Severity: **high**
- Fix: Only allow the project directories the agent really needs.
- References: <https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem>

## DV017: Reverse proxy publishes <product> without authentication

- Severity: **high**
- Fix: Add authentication in the proxy (Nginx: auth_basic or auth_request; Caddy: basic_auth or forward_auth), or restrict the block to trusted IPs.
- References: <https://thehackernews.com/2024/06/critical-rce-vulnerability-discovered.html>, <https://qdrant.tech/documentation/guides/security>

## DV018: Secrets file not protected from Git

- Severity: **medium**
- Fix: Add the file to .gitignore. If it was already committed, rotate every secret it contains, then remove it from the history.
- References: <https://git-scm.com/docs/gitignore>

## DV101: Ollama answers without authentication

- Severity: **high**
- Fix: Bind Ollama to 127.0.0.1 (OLLAMA_HOST=127.0.0.1) or firewall the port, and expose it only through an authenticating reverse proxy.
- References: <https://thehackernews.com/2024/06/critical-rce-vulnerability-discovered.html>

## DV102: AI service port reachable

- Severity: **medium**
- Fix: Check that this exposure is intended. If not, bind the service to 127.0.0.1 or block the port at the firewall.

## DV103: Running Ollama version is vulnerable

- Severity: **critical**
- Fix: Upgrade Ollama to <fixed> or later, ideally the latest release.
- References: <https://osv.dev/vulnerability/CVE-2024-37032>

## DV104: Qdrant answers without authentication

- Severity: **high**
- Fix: Set QDRANT__SERVICE__API_KEY and restrict network access to the Qdrant ports.
- References: <https://qdrant.tech/documentation/guides/security>

## DV105: OpenClaw native security audit

- Severity: **info**
- Fix: Follow the recommendations printed by OpenClaw.
- References: <https://docs.openclaw.ai/gateway/security/network-exposure.md>
