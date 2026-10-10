#!/usr/bin/env bash
# Scan périodique de Dave. Fonctionne avec une installation native (paquet .deb) ou Docker.
# Léger : quelques secondes de calcul, ~25 Mo de RAM, priorité minimale, lecture seule.
set -uo pipefail

[ -f /etc/default/dave ] && . /etc/default/dave

BASE="${DAVE_BASE:-/var/lib/dave}"
REPORTS="$BASE/reports"
MODE="${DAVE_MODE:-auto}"                 # auto | native | docker
IMAGE="${DAVE_IMAGE:-dave:latest}"
SCAN_DIRS="${DAVE_SCAN_DIRS:-}"           # dossiers de docker-compose, séparés par des espaces
OPENCLAW_DIR="${OPENCLAW_DIR:-}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
KEEP_DAYS="${DAVE_KEEP_DAYS:-30}"

if [ -z "$SCAN_DIRS" ]; then
  for d in /var/lib/casaos/apps /opt/stacks /srv/docker; do [ -d "$d" ] && SCAN_DIRS="$SCAN_DIRS $d"; done
fi
DIRS=()
for d in $SCAN_DIRS; do [ -d "$d" ] && DIRS+=("$d"); done
[ "${#DIRS[@]}" -eq 0 ] && DIRS=("$BASE/empty") && mkdir -p "$BASE/empty"

if [ "$MODE" = "auto" ]; then
  if command -v dave >/dev/null 2>&1 && dave --version >/dev/null 2>&1 && [ "$(command -v dave)" != /usr/local/bin/dave ]; then
    MODE=native
  else
    MODE=docker
  fi
fi

mkdir -p "$REPORTS"
TODAY="$(date +%F)"
LAST="$(ls -1 "$REPORTS"/20*.json 2>/dev/null | grep -v "/$TODAY.json$" | tail -n 1 || true)"
CONFIG=()
[ -f "$BASE/dave.yml" ] && CONFIG=(--config "$BASE/dave.yml")
ARGS=(scan "${DIRS[@]}" --lang "${DAVE_LANG:-fr}" --format html -o "$REPORTS/latest.html"
      --badge "$REPORTS/badge.svg" --json-out "$REPORTS/$TODAY.json" --fail-on critical "${CONFIG[@]}")
[ -n "$LAST" ] && ARGS+=(--baseline "$LAST")
[ -n "$OPENCLAW_DIR" ] && [ -f "$OPENCLAW_DIR/openclaw.json" ] && ARGS+=(--openclaw-config "$OPENCLAW_DIR/openclaw.json")

if [ "$MODE" = "native" ]; then
  nice -n 19 ionice -c 3 dave "${ARGS[@]}" > /dev/null
  RC=$?
else
  # Chaque chemin est monté au même endroit, en lecture seule (sauf le dossier des rapports).
  MOUNTS=(-v "$REPORTS:$REPORTS")
  for p in "${DIRS[@]}" /etc/ufw /etc/systemd/system /lib/systemd/system "$OPENCLAW_DIR" "$BASE/dave.yml"; do
    [ -n "$p" ] && [ -e "$p" ] && MOUNTS+=(-v "$p:$p:ro")
  done
  docker run --rm --name dave-scan --network host --user 0 --read-only \
    --cap-drop ALL --cap-add DAC_READ_SEARCH --security-opt no-new-privileges \
    --cpus 1 --cpu-shares 128 --memory 128m --pids-limit 64 \
    "${MOUNTS[@]}" "$IMAGE" "${ARGS[@]}" > /dev/null
  RC=$?
fi
[ "$RC" -gt 1 ] && echo "dave: échec du scan (code $RC)" >&2 && exit "$RC"

REPORT="$REPORTS/$TODAY.json"
GRADE="$(grep -o '"grade": "[A-F]"' "$REPORT" | grep -o '[A-F]' | head -n 1)"
NEW="$(grep -o '"new": [0-9]*' "$REPORT" | grep -o '[0-9]*$' | head -n 1)"
echo "Dave ($MODE) : note ${GRADE:-?}, nouveaux problèmes : ${NEW:-0}, rapport : $REPORTS/latest.html"

if [ -n "$DISCORD_WEBHOOK" ] && [ "${NEW:-0}" -gt 0 ]; then
  MSG="Dave ($(hostname)) : ${NEW} nouveau(x) problème(s), note ${GRADE}. Rapport : $REPORTS/latest.html"
  curl -fsS -m 10 -H "Content-Type: application/json" -d "{\"content\": \"$MSG\"}" "$DISCORD_WEBHOOK" > /dev/null \
    || echo "dave: alerte Discord non envoyée" >&2
fi
# Nouvelle version de Dave ? Une seule notification par version.
if [ -z "${DAVE_NO_UPDATE_CHECK:-}" ]; then
  if [ "$MODE" = "native" ]; then
    UPD="$(dave update-check --plain 2>/dev/null)"; URC=$?
  else
    UPD="$(docker run --rm --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
      --memory 64m -e DAVE_INSTALL_METHOD=docker-wrapper "$IMAGE" update-check --plain 2>/dev/null)"; URC=$?
  fi
  if [ "$URC" -eq 10 ] && [ -n "$UPD" ] && [ "$(cat "$BASE/.notified-version" 2>/dev/null)" != "$UPD" ]; then
    echo "$UPD" > "$BASE/.notified-version"
    echo "Dave $UPD est disponible. Mise à jour : https://github.com/dave-sec/dave/releases"
    if [ -n "$DISCORD_WEBHOOK" ]; then
      curl -fsS -m 10 -H "Content-Type: application/json" \
        -d "{\"content\": \"Dave ($(hostname)) : la version $UPD est disponible. Lance 'dave update-check' pour la commande de mise à jour.\"}" \
        "$DISCORD_WEBHOOK" > /dev/null || true
    fi
  fi
fi

find "$REPORTS" -name '20*.json' -mtime +"$KEEP_DAYS" -delete
exit 0
