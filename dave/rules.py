"""Définition des règles : sévérité et textes (en / fr)."""
from __future__ import annotations

RULES: dict[str, dict] = {
    "DV001": {
        "refs": ["https://dev.to/techiemike/self-hosted-ai-security-what-every-ollama-user-should-know-29ie", "https://docs.docker.com/engine/network/packet-filtering-firewalls/"],
        "severity": "high",
        "en": {
            "title": "AI service published on all network interfaces",
            "detail": "{service} publishes port {port} without a host IP, so Docker binds it on 0.0.0.0: any machine that can reach this host can use the service.",
            "fix": "Bind the port to localhost ('127.0.0.1:{port}:{target}') and put an authenticating reverse proxy in front if remote access is needed.",
        },
        "fr": {
            "title": "Service d'IA publié sur toutes les interfaces réseau",
            "detail": "{service} publie le port {port} sans adresse hôte : Docker l'ouvre sur 0.0.0.0 et toute machine qui joint cet hôte peut utiliser le service.",
            "fix": "Limitez le port à la machine locale ('127.0.0.1:{port}:{target}') et placez un reverse proxy avec authentification devant si un accès distant est nécessaire.",
        },
    },
    "DV002": {
        "refs": ["https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"],
        "severity": "critical",
        "en": {
            "title": "Docker socket mounted into a container",
            "detail": "{service} mounts the Docker socket: whoever controls this container controls the Docker daemon, which means root on the host.",
            "fix": "Remove the docker.sock volume. If the feature is required, use a filtering socket proxy that only allows the needed API calls.",
        },
        "fr": {
            "title": "Socket Docker monté dans un conteneur",
            "detail": "{service} monte le socket Docker : qui contrôle ce conteneur contrôle le démon Docker, donc l'hôte en root.",
            "fix": "Retirez le volume docker.sock. Si la fonction est indispensable, passez par un proxy de socket qui n'autorise que les appels nécessaires.",
        },
    },
    "DV003": {
        "refs": ["https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"],
        "severity": "high",
        "en": {
            "title": "Privileged container",
            "detail": "{service} runs with privileged: true, which disables most container isolation.",
            "fix": "Remove privileged: true and grant only the specific devices or capabilities needed (for GPUs, use the 'deploy.resources.reservations.devices' syntax).",
        },
        "fr": {
            "title": "Conteneur privilégié",
            "detail": "{service} tourne avec privileged: true, ce qui désactive l'essentiel de l'isolation du conteneur.",
            "fix": "Retirez privileged: true et n'accordez que les périphériques ou capacités nécessaires (pour un GPU, utilisez la syntaxe 'deploy.resources.reservations.devices').",
        },
    },
    "DV004": {
        "refs": ["https://docs.docker.com/engine/network/drivers/host/"],
        "severity": "medium",
        "en": {
            "title": "Container shares the host network",
            "detail": "{service} uses network_mode: host, so every port it opens is directly exposed on the host's interfaces.",
            "fix": "Use a dedicated Docker network and publish only the ports you need, bound to 127.0.0.1.",
        },
        "fr": {
            "title": "Conteneur sur le réseau de l'hôte",
            "detail": "{service} utilise network_mode: host : chaque port qu'il ouvre est directement exposé sur les interfaces de l'hôte.",
            "fix": "Utilisez un réseau Docker dédié et ne publiez que les ports nécessaires, limités à 127.0.0.1.",
        },
    },
    "DV005": {
        "refs": ["https://dev.to/techiemike/self-hosted-ai-security-what-every-ollama-user-should-know-29ie", "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"],
        "severity": "medium",
        "en": {
            "title": "AI service runs as root",
            "detail": "{service} has no 'user:' setting (or runs as root). A flaw in the service would give the attacker root inside the container.",
            "fix": "Add a non-root 'user:' (for example \"1000:1000\") if the image supports it, and fix volume ownership accordingly.",
        },
        "fr": {
            "title": "Service d'IA exécuté en root",
            "detail": "{service} n'a pas de réglage 'user:' (ou tourne en root). Une faille du service donnerait à l'attaquant les droits root dans le conteneur.",
            "fix": "Ajoutez un 'user:' non root (par exemple \"1000:1000\") si l'image le permet, et ajustez les droits des volumes.",
        },
    },
    "DV006": {
        "refs": ["https://docs.docker.com/build/building/best-practices/"],
        "severity": "low",
        "en": {
            "title": "Unpinned image version",
            "detail": "{service} uses '{image}'. 'latest' or a missing tag changes silently on each pull, including to vulnerable versions.",
            "fix": "Pin an explicit version tag (or digest) and update it deliberately.",
        },
        "fr": {
            "title": "Version d'image non figée",
            "detail": "{service} utilise '{image}'. 'latest' ou l'absence de tag change à chaque pull, y compris vers une version vulnérable.",
            "fix": "Fixez une version explicite (tag ou digest) et mettez-la à jour volontairement.",
        },
    },
    "DV007": {
        "refs": ["https://docs.openwebui.com/getting-started/env-configuration"],
        "severity": "high",
        "en": {
            "title": "Open WebUI authentication disabled",
            "detail": "{service} sets WEBUI_AUTH to false: anyone who reaches the interface can use your models and read conversations.",
            "fix": "Remove WEBUI_AUTH=False (authentication is on by default) and create user accounts.",
        },
        "fr": {
            "title": "Authentification d'Open WebUI désactivée",
            "detail": "{service} règle WEBUI_AUTH à false : quiconque atteint l'interface peut utiliser vos modèles et lire les conversations.",
            "fix": "Supprimez WEBUI_AUTH=False (l'authentification est active par défaut) et créez des comptes utilisateurs.",
        },
    },
    "DV008": {
        "refs": ["https://github.com/ollama/ollama/blob/main/docs/faq.md"],
        "severity": "medium",
        "en": {
            "title": "Ollama accepts requests from any web origin",
            "detail": "{service} sets OLLAMA_ORIGINS to '*': any website opened in a browser on this network can send requests to Ollama.",
            "fix": "List only the origins you use, for example OLLAMA_ORIGINS=http://localhost:3000.",
        },
        "fr": {
            "title": "Ollama accepte les requêtes de n'importe quel site web",
            "detail": "{service} règle OLLAMA_ORIGINS à '*' : n'importe quel site ouvert dans un navigateur de ce réseau peut envoyer des requêtes à Ollama.",
            "fix": "N'autorisez que les origines utiles, par exemple OLLAMA_ORIGINS=http://localhost:3000.",
        },
    },
    "DV009": {
        "refs": ["https://docs.docker.com/compose/how-tos/use-secrets/"],
        "severity": "medium",
        "en": {
            "title": "Secret written in clear in the compose file",
            "detail": "{service} defines {key} with a literal value. The secret ends up in Git history, backups and screenshots.",
            "fix": "Move the value to a .env file excluded from Git (or Docker secrets) and reference it as ${{{key}}}.",
        },
        "fr": {
            "title": "Secret écrit en clair dans le fichier compose",
            "detail": "{service} définit {key} avec une valeur en clair. Le secret finit dans l'historique Git, les sauvegardes et les captures d'écran.",
            "fix": "Déplacez la valeur dans un fichier .env exclu de Git (ou un secret Docker) et référencez-la avec ${{{key}}}.",
        },
    },
    "DV101": {
        "refs": ["https://thehackernews.com/2024/06/critical-rce-vulnerability-discovered.html"],
        "severity": "high",
        "en": {
            "title": "Ollama answers without authentication",
            "detail": "{target} answered /api/tags and listed {count} model(s) without any credentials. Ollama has no built-in authentication.",
            "fix": "Bind Ollama to 127.0.0.1 (OLLAMA_HOST=127.0.0.1) or firewall the port, and expose it only through an authenticating reverse proxy.",
        },
        "fr": {
            "title": "Ollama répond sans authentification",
            "detail": "{target} a répondu à /api/tags et listé {count} modèle(s) sans aucun identifiant. Ollama n'a pas d'authentification intégrée.",
            "fix": "Limitez Ollama à 127.0.0.1 (OLLAMA_HOST=127.0.0.1) ou filtrez le port au pare-feu, et exposez-le uniquement derrière un reverse proxy avec authentification.",
        },
    },
    "DV102": {
        "refs": [],
        "severity": "medium",
        "en": {
            "title": "AI service port reachable",
            "detail": "Port {port} ({service}) accepts connections on {target}.",
            "fix": "Check that this exposure is intended. If not, bind the service to 127.0.0.1 or block the port at the firewall.",
        },
        "fr": {
            "title": "Port de service d'IA joignable",
            "detail": "Le port {port} ({service}) accepte les connexions sur {target}.",
            "fix": "Vérifiez que cette exposition est voulue. Sinon, limitez le service à 127.0.0.1 ou bloquez le port au pare-feu.",
        },
    },
    "DV010": {
        "severity": "high",
        "refs": ["https://qdrant.tech/documentation/guides/security"],
        "en": {
            "title": "Qdrant runs without an API key",
            "detail": "{service} does not set QDRANT__SERVICE__API_KEY. Self-hosted Qdrant has no authentication by default: anyone who reaches it can read, write or delete every collection.",
            "fix": "Set QDRANT__SERVICE__API_KEY from a secret (for example ${{QDRANT_API_KEY}} in a .env file) and pass the key in your clients.",
        },
        "fr": {
            "title": "Qdrant tourne sans clé d'API",
            "detail": "{service} ne définit pas QDRANT__SERVICE__API_KEY. Qdrant auto-hébergé n'a aucune authentification par défaut : quiconque l'atteint peut lire, modifier ou supprimer toutes les collections.",
            "fix": "Définissez QDRANT__SERVICE__API_KEY à partir d'un secret (par exemple ${{QDRANT_API_KEY}} dans un fichier .env) et transmettez la clé dans vos clients.",
        },
    },
    "DV011": {
        "severity": "critical",
        "refs": ["https://osv.dev/vulnerability/CVE-2024-37032"],
        "en": {
            "title": "Known vulnerable {product} version",
            "detail": "{service} runs {product} {version}, affected by {cve} (fixed in {fixed}).",
            "fix": "Upgrade to {fixed} or later, ideally the latest release, and pin that version.",
        },
        "fr": {
            "title": "Version de {product} vulnérable connue",
            "detail": "{service} utilise {product} {version}, touché par {cve} (corrigé en {fixed}).",
            "fix": "Passez en {fixed} ou plus récent, idéalement la dernière version, et figez cette version.",
        },
    },
    "DV012": {
        "severity": "high",
        "refs": ["https://github.com/ollama/ollama/blob/main/docs/faq.md"],
        "en": {
            "title": "Ollama configured to listen on all interfaces",
            "detail": "{service} sets OLLAMA_HOST={value}. Ollama listens on 127.0.0.1 by default; this setting exposes its unauthenticated API to the network.",
            "fix": "Remove the override or set OLLAMA_HOST=127.0.0.1, then 'systemctl daemon-reload && systemctl restart ollama'. Use an authenticating reverse proxy for remote access.",
        },
        "fr": {
            "title": "Ollama configuré pour écouter sur toutes les interfaces",
            "detail": "{service} règle OLLAMA_HOST={value}. Ollama écoute sur 127.0.0.1 par défaut : ce réglage expose son API sans authentification au réseau.",
            "fix": "Supprimez ce réglage ou mettez OLLAMA_HOST=127.0.0.1, puis 'systemctl daemon-reload && systemctl restart ollama'. Passez par un reverse proxy avec authentification pour un accès distant.",
        },
    },
    "DV103": {
        "severity": "critical",
        "refs": ["https://osv.dev/vulnerability/CVE-2024-37032"],
        "en": {
            "title": "Running Ollama version is vulnerable",
            "detail": "{target} reports Ollama {version}, affected by {cve} (fixed in {fixed}).",
            "fix": "Upgrade Ollama to {fixed} or later, ideally the latest release.",
        },
        "fr": {
            "title": "La version d'Ollama en service est vulnérable",
            "detail": "{target} annonce Ollama {version}, touché par {cve} (corrigé en {fixed}).",
            "fix": "Mettez Ollama à jour en {fixed} ou plus récent, idéalement la dernière version.",
        },
    },
    "DV104": {
        "severity": "high",
        "refs": ["https://qdrant.tech/documentation/guides/security"],
        "en": {
            "title": "Qdrant answers without authentication",
            "detail": "{target} listed its collections without any API key.",
            "fix": "Set QDRANT__SERVICE__API_KEY and restrict network access to the Qdrant ports.",
        },
        "fr": {
            "title": "Qdrant répond sans authentification",
            "detail": "{target} a listé ses collections sans aucune clé d'API.",
            "fix": "Définissez QDRANT__SERVICE__API_KEY et limitez l'accès réseau aux ports de Qdrant.",
        },
    },
    "DV013": {
        "severity": "medium",
        "refs": ["https://docs.openclaw.ai/gateway/security/network-exposure.md"],
        "en": {
            "title": "OpenClaw gateway listens beyond loopback",
            "detail": "{source} sets gateway.bind to '{bind}'. OpenClaw's default is 'loopback'; non-loopback binds expand the attack surface of an agent that can run tools on this machine.",
            "fix": "Set gateway.bind to 'loopback' and reach the gateway through an SSH tunnel or Tailscale Serve. If you must bind to the LAN, firewall port {port} to a tight source-IP allowlist and keep gateway auth enabled.",
        },
        "fr": {
            "title": "Passerelle OpenClaw ouverte au-delà de la machine locale",
            "detail": "{source} règle gateway.bind sur '{bind}'. La valeur par défaut d'OpenClaw est 'loopback' : les autres modes élargissent la surface d'attaque d'un agent capable d'exécuter des outils sur cette machine.",
            "fix": "Repassez gateway.bind en 'loopback' et accédez à la passerelle par un tunnel SSH ou Tailscale Serve. Si le réseau local est indispensable, filtrez le port {port} au pare-feu sur une liste d'IP précise et gardez l'authentification de la passerelle.",
        },
    },
    "DV105": {
        "severity": "info",
        "refs": ["https://docs.openclaw.ai/gateway/security/network-exposure.md"],
        "en": {
            "title": "OpenClaw native security audit",
            "detail": "Output of 'openclaw security audit' (exit code {code}). Dave does not interpret it: review it below.",
            "fix": "Follow the recommendations printed by OpenClaw.",
        },
        "fr": {
            "title": "Audit de sécurité natif d'OpenClaw",
            "detail": "Résultat de 'openclaw security audit' (code de sortie {code}). Dave ne l'interprète pas : relisez-le ci-dessous.",
            "fix": "Suivez les recommandations affichées par OpenClaw.",
        },
    },
    "DV014": {
        "severity": "high",
        "refs": ["https://docs.docker.com/engine/network/packet-filtering-firewalls/"],
        "en": {
            "title": "Docker bypasses your UFW firewall",
            "detail": "UFW is enabled, but {source} publishes {ports} on all interfaces. Docker inserts its own iptables rules, so these ports are reachable even if UFW denies them.",
            "fix": "Bind published ports to 127.0.0.1 (see DV001 and 'dave fix'), or filter Docker traffic in the DOCKER-USER chain. Do not rely on UFW alone for containers.",
        },
        "fr": {
            "title": "Docker contourne votre pare-feu UFW",
            "detail": "UFW est actif, mais {source} publie {ports} sur toutes les interfaces. Docker ajoute ses propres règles iptables : ces ports restent joignables même si UFW les bloque.",
            "fix": "Limitez les ports publiés à 127.0.0.1 (voir DV001 et 'dave fix') ou filtrez le trafic Docker dans la chaîne DOCKER-USER. Ne comptez pas sur UFW seul pour les conteneurs.",
        },
    },
    "DV015": {
        "severity": "medium",
        "refs": ["https://docs.docker.com/compose/how-tos/use-secrets/"],
        "en": {
            "title": "Secret in clear in an MCP client configuration",
            "detail": "{source} gives the MCP server '{service}' a literal value for {key}. Any program or agent that can read this file gets the secret.",
            "fix": "Reference the secret from the environment or a secret manager instead of writing it in the file, and restrict the file permissions (chmod 600).",
        },
        "fr": {
            "title": "Secret en clair dans une configuration de client MCP",
            "detail": "{source} donne au serveur MCP '{service}' une valeur en clair pour {key}. Tout programme ou agent capable de lire ce fichier récupère le secret.",
            "fix": "Référencez le secret depuis l'environnement ou un gestionnaire de secrets au lieu de l'écrire dans le fichier, et restreignez les droits du fichier (chmod 600).",
        },
    },
    "DV016": {
        "severity": "high",
        "refs": ["https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem"],
        "en": {
            "title": "MCP filesystem server can reach the whole disk or home",
            "detail": "{source} lets the MCP server '{service}' access '{path}'. An agent tricked by prompt injection could read SSH keys, tokens or any personal file.",
            "fix": "Only allow the project directories the agent really needs.",
        },
        "fr": {
            "title": "Serveur MCP de fichiers avec accès à tout le disque ou au dossier personnel",
            "detail": "{source} autorise le serveur MCP '{service}' à accéder à '{path}'. Un agent manipulé par injection de prompt pourrait lire vos clés SSH, vos jetons ou n'importe quel fichier personnel.",
            "fix": "N'autorisez que les dossiers de projet dont l'agent a réellement besoin.",
        },
    },
    "DV017": {
        "severity": "high",
        "refs": ["https://thehackernews.com/2024/06/critical-rce-vulnerability-discovered.html", "https://qdrant.tech/documentation/guides/security"],
        "en": {
            "title": "Reverse proxy publishes {product} without authentication",
            "detail": "{source} forwards traffic to {product} ({target}) with no authentication directive in the same block. {product} has no authentication of its own by default.",
            "fix": "Add authentication in the proxy (Nginx: auth_basic or auth_request; Caddy: basic_auth or forward_auth), or restrict the block to trusted IPs.",
        },
        "fr": {
            "title": "Le reverse proxy publie {product} sans authentification",
            "detail": "{source} transmet le trafic vers {product} ({target}) sans directive d'authentification dans le même bloc. {product} n'a pas d'authentification propre par défaut.",
            "fix": "Ajoutez une authentification dans le proxy (Nginx : auth_basic ou auth_request ; Caddy : basic_auth ou forward_auth), ou limitez le bloc à des IP de confiance.",
        },
    },
    "DV018": {
        "severity": "medium",
        "refs": ["https://git-scm.com/docs/gitignore"],
        "en": {
            "title": "Secrets file not protected from Git",
            "detail": "{source} is {state}. Its secrets can end up in the repository history, which is very hard to clean afterwards.",
            "fix": "Add the file to .gitignore. If it was already committed, rotate every secret it contains, then remove it from the history.",
        },
        "fr": {
            "title": "Fichier de secrets non protégé de Git",
            "detail": "{source} est {state}. Ses secrets peuvent finir dans l'historique du dépôt, très difficile à nettoyer ensuite.",
            "fix": "Ajoutez le fichier au .gitignore. S'il a déjà été commité, changez tous les secrets qu'il contient, puis retirez-le de l'historique.",
        },
    },
}

LOCAL_NOTE = {
    "en": " Target is this machine: acceptable for single-user local use, but any local program or user can reach it.",
    "fr": " La cible est cette machine : acceptable pour un usage local à un seul utilisateur, mais tout programme ou utilisateur local peut l'atteindre.",
}


def text(rule_id: str, lang: str, **kw) -> tuple[str, str, str]:
    rule = RULES[rule_id]
    t = rule.get(lang) or rule["en"]
    return t["title"], t["detail"].format(**kw), t["fix"].format(**kw)
