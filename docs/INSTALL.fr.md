# Installer Dave

Compatible Debian 11, 12, 13, Ubuntu 22.04 et plus, et toute machine avec Docker (amd64 et arm64).

## Méthode recommandée : l'installateur

    git clone https://github.com/dave-sec/dave && cd dave     # ou décompresser le zip
    sudo ./install.sh --timer

L'installateur choisit seul :
- **paquet .deb natif** si Python 3.9+ et apt sont présents (Debian 11 : Python 3.9 ; 12 : 3.11 ; 13 : 3.13) ;
- **Docker** sinon, ou si tu le forces avec `--docker`.

Dans les deux cas, la commande `dave` s'utilise de la même façon.

## Les autres méthodes

    sudo apt install ./dave_0.4.0_all.deb                       # paquet seul
    sudo ./install.sh --docker                                  # image construite sur place
    sudo ./install.sh --docker --image ghcr.io/dave-sec/dave:latest   # image publiée (après la 1re release)
    pipx install git+https://github.com/dave-sec/dave              # autre OS avec Python 3.9+

Sur Debian 12 et plus, `pip install` dans le Python du système est bloqué (PEP 668) : utilise le .deb, Docker ou pipx.

## Configuration : /etc/default/dave

    DAVE_BASE=/var/lib/dave            # rapports et dave.yml
    DAVE_SCAN_DIRS=                    # vide = /var/lib/casaos/apps, /opt/stacks, /srv/docker s'ils existent
    OPENCLAW_DIR=                      # ex. /home/<user>/.openclaw
    DISCORD_WEBHOOK=                   # alerte seulement s'il y a du nouveau
    DAVE_KEEP_DAYS=30

## Utilisation

    sudo dave scan /var/lib/casaos/apps --lang fr
    sudo dave fix -i /var/lib/casaos/apps/<app>/docker-compose.yml
    sudo systemctl start dave-scan.service && journalctl -u dave-scan.service -n 5
    systemctl list-timers dave-scan.timer

## Consommation

- Aucun service permanent : un scan par nuit, quelques secondes.
- Mesuré : environ 25 Mo de RAM au maximum, sur une arborescence de 60 000 fichiers.
- Priorité CPU et disque minimale ; en Docker, plafond de 1 cœur et 128 Mo.
- Parcours limité à 4 niveaux, bibliothèques photo et vidéo ignorées.
- `--explain` (IA locale) est à éviter sur une machine sans GPU.

## Exemple : ZimaBlade sous CasaOS (Debian 11)

    sudo ./install.sh --timer        # choisit le .deb (Python 3.9 présent) ou --docker si tu préfères
    sudo nano /etc/default/dave      # DAVE_BASE=/DATA/dave pour garder les rapports sur le SSD
    sudo dave scan /var/lib/casaos/apps --lang fr

Après une correction d'app CasaOS : `sudo casaos-app-management-cli app apply <app> /var/lib/casaos/apps/<app>/docker-compose.yml`,
ou redémarrage de l'app depuis l'interface. Limiter un port à 127.0.0.1 coupe l'accès depuis le réseau local
et depuis un cloudflared en conteneur : vérifie l'usage de l'app avant.

## Mettre à jour

Dave te prévient (terminal et Discord). Ensuite :

    dave update-check                  # affiche la commande adaptée à ton installation
    sha256sum -c SHA256SUMS            # vérifier le .deb téléchargé depuis la release
    sudo apt install ./dave_<version>_all.deb

## Désinstaller

    sudo ./install.sh --uninstall
