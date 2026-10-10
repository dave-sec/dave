#!/usr/bin/env bash
# Installateur de Dave pour Debian 11, 12, 13 et Ubuntu 22.04+ (et toute machine avec Docker).
#
#   sudo ./install.sh                 # choix automatique : paquet .deb si possible, sinon Docker
#   sudo ./install.sh --deb           # paquet Debian natif
#   sudo ./install.sh --docker        # image Docker construite depuis ce dossier
#   sudo ./install.sh --docker --image ghcr.io/dave-sec/dave:0.4.0   # image publiée
#   sudo ./install.sh --timer         # active en plus le scan automatique chaque nuit
#   sudo ./install.sh --uninstall
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

MODE=auto IMAGE="" TIMER=0 UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --deb) MODE=deb ;;
    --docker) MODE=docker ;;
    --image) IMAGE="$2"; shift ;;
    --timer) TIMER=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'Erreur : %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "lance ce script avec sudo."

if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now dave-scan.timer >/dev/null 2>&1 || true
  if dpkg -s dave >/dev/null 2>&1; then apt-get remove -y dave; fi
  rm -f /usr/local/bin/dave /etc/systemd/system/dave-scan.service /etc/systemd/system/dave-scan.timer
  rm -rf /usr/local/lib/dave
  command -v docker >/dev/null 2>&1 && docker rmi dave:latest >/dev/null 2>&1 || true
  systemctl daemon-reload 2>/dev/null || true
  say "Dave désinstallé. Rapports et configuration conservés : /var/lib/dave, /etc/default/dave"
  exit 0
fi

. /etc/os-release 2>/dev/null || true
say "Système détecté : ${PRETTY_NAME:-inconnu}"
py_ok() { command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; }

if [ "$MODE" = auto ]; then
  if command -v apt-get >/dev/null 2>&1 && command -v dpkg-deb >/dev/null 2>&1 && py_ok; then
    MODE=deb
  elif command -v docker >/dev/null 2>&1; then
    MODE=docker
  else
    die "ni Python 3.9+ avec apt, ni Docker : installe l'un des deux puis relance."
  fi
fi

if [ "$MODE" = deb ]; then
  py_ok || die "Python 3.9 ou plus récent est requis pour le paquet .deb (utilise --docker sinon)."
  say "Construction du paquet .deb"
  DEB="$(./packaging/build-deb.sh)"
  say "Installation de $DEB (dépendances : python3, python3-yaml)"
  apt-get update -qq
  apt-get install -y "./$DEB"
  UNIT_DIR=/lib/systemd/system
  sed -i 's/^DAVE_MODE=.*/DAVE_MODE=native/' /etc/default/dave
else
  command -v docker >/dev/null 2>&1 || die "Docker n'est pas installé."
  if [ -n "$IMAGE" ]; then
    say "Téléchargement de l'image $IMAGE"
    docker pull "$IMAGE"
    docker tag "$IMAGE" dave:latest
  else
    say "Construction de l'image Docker (quelques minutes sur une petite machine)"
    docker build -q -t dave:latest . >/dev/null
  fi
  install -d /usr/local/lib/dave /var/lib/dave/reports
  install -m 755 packaging/dave-docker /usr/local/bin/dave
  install -m 755 packaging/dave-daily.sh /usr/local/lib/dave/dave-daily.sh
  [ -f /etc/default/dave ] || install -m 600 packaging/default /etc/default/dave
  sed -i 's/^DAVE_MODE=.*/DAVE_MODE=docker/' /etc/default/dave
  sed 's#/usr/lib/dave/dave-daily.sh#/usr/local/lib/dave/dave-daily.sh#' packaging/systemd/dave-scan.service \
    > /etc/systemd/system/dave-scan.service
  install -m 644 packaging/systemd/dave-scan.timer /etc/systemd/system/dave-scan.timer
  UNIT_DIR=/etc/systemd/system
fi
chmod 600 /etc/default/dave

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  if [ "$TIMER" -eq 1 ]; then
    systemctl enable --now dave-scan.timer
    say "Scan automatique activé (chaque nuit vers 4 h 30)"
  fi
fi

say "Dave $(dave --version 2>/dev/null | awk '{print $2}') installé en mode $MODE"
cat << MSG

  Scan manuel     : sudo dave scan /var/lib/casaos/apps --lang fr
  Configuration   : sudo nano /etc/default/dave   (dossiers, OpenClaw, webhook Discord)
  Scan nocturne   : sudo systemctl enable --now dave-scan.timer
  Rapports        : /var/lib/dave/reports/latest.html  (ou DAVE_BASE)
MSG
