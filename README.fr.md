# Dave

**Audit de sécurité pour les stacks d'IA auto-hébergées.** Dave vérifie OpenClaw, Ollama, Open WebUI, n8n, LiteLLM, vLLM,
Qdrant et compagnie, à la recherche des erreurs qui les exposent à tout votre réseau, voire à internet, et corrige
les plus simples pour vous.

- **100 % local** : aucun compte, aucune API cloud. Les explications optionnelles viennent de *votre* modèle Ollama.
- **Configuration, hôte et réseau** : fichiers docker-compose, installation systemd d'Ollama, services en fonctionnement.
- **Règles sourcées uniquement** : chaque contrôle renvoie à la documentation ou à l'avis de sécurité qui le justifie.
- **Utilisable par les agents IA** : `dave mcp` expose Dave comme serveur MCP en lecture seule.
- **Prêt pour la CI** : sortie SARIF, action GitHub, hook pre-commit, codes de sortie.

## Installation

Debian 11, 12, 13, Ubuntu 22.04+ et toute machine avec Docker (amd64 et arm64). Python 3.9+.

    git clone https://github.com/dave-sec/dave && cd dave
    sudo ./install.sh            # paquet .deb si possible, sinon Docker
    sudo ./install.sh --timer    # idem, avec un scan automatique chaque nuit

Guide complet : [docs/INSTALL.fr.md](docs/INSTALL.fr.md).

## Utilisation

    dave scan --lang fr               # compose du dossier courant, installation hôte, sonde de localhost
    dave fix ./stack --lang fr        # aperçu des correctifs sûrs
    dave fix ./stack --write          # les appliquer (copie .bak conservée)
    dave fix ./stack -i               # valider chaque correctif un par un, puis voir la nouvelle note
    dave scan --format html -o rapport.html --badge dave.svg   # rapport partageable et badge
    dave host --with-openclaw-audit   # Ollama (systemd), passerelle OpenClaw + audit natif d'OpenClaw
    dave mcp                          # serveur MCP pour agents IA (lecture seule)
    dave probe --host 192.168.1.20    # une machine QUI VOUS APPARTIENT
    dave scan --explain --model llama3.2 --lang fr

Chaque rapport se termine par une note de A à F. Pour fixer le français par défaut : `export DAVE_LANG=fr`.

## Mises à jour

Dave prévient quand une nouvelle version sort, mais ne se met jamais à jour tout seul (un outil de sécurité
qui remplace son propre code depuis internet serait un risque).

- Dans le terminal : une ligne après le rapport.
- `dave update-check` : vérifie tout de suite et donne la bonne commande selon ton installation.
- Scan nocturne : un message Discord par nouvelle version, jamais deux fois.
- Au plus une requête par jour vers l'API publique de GitHub. Désactivable : `DAVE_NO_UPDATE_CHECK=1`.
- Chaque release contient un fichier `SHA256SUMS` pour vérifier le .deb : `sha256sum -c SHA256SUMS`.

## Agents IA (MCP)

Le serveur MCP n'écrit jamais de fichier (les correctifs sont seulement proposés), ne lit que sous
`DAVE_MCP_ROOT` et ne sonde que les hôtes listés dans `DAVE_MCP_ALLOWED_HOSTS` (par défaut `127.0.0.1`) :
un agent manipulé par injection de prompt ne peut pas le retourner contre d'autres machines.

## Dave Pro

Surveillance continue de vos machines, alertes Discord, Slack ou ntfy dès qu'un nouveau problème apparaît, historique de la note.
Achetez une licence, puis `pip install dave-pro && dave-pro activate <CLÉ>`. Dave reste gratuit et open source.

## Cadre légal

Ne sondez que des machines qui vous appartiennent ou que vous êtes explicitement autorisé à tester (l'accès
frauduleux à un système est puni par l'article 323-1 du Code pénal). La sonde n'envoie que des requêtes GET
en lecture et ne tente jamais d'exploitation.

## Licence

AGPL-3.0-or-later.
