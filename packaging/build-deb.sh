#!/usr/bin/env bash
# Construit dist/dave_<version>_all.deb : Python pur, compatible Debian 11, 12, 13 et Ubuntu 22.04+.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' dave/__init__.py)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

install -d "$ROOT/DEBIAN" "$ROOT/usr/lib/python3/dist-packages/dave" "$ROOT/usr/bin" \
  "$ROOT/usr/lib/dave" "$ROOT/lib/systemd/system" "$ROOT/usr/share/doc/dave" "$ROOT/etc/default"
install -m 644 dave/*.py "$ROOT/usr/lib/python3/dist-packages/dave/"
install -m 755 packaging/dave-daily.sh "$ROOT/usr/lib/dave/dave-daily.sh"
install -m 644 packaging/systemd/dave-scan.service packaging/systemd/dave-scan.timer "$ROOT/lib/systemd/system/"
install -m 644 packaging/default "$ROOT/etc/default/dave"
install -m 644 README.md CHANGELOG.md "$ROOT/usr/share/doc/dave/"
cat > "$ROOT/usr/share/doc/dave/copyright" << COPY
Dave - security audit for self-hosted AI stacks.
License: AGPL-3.0-or-later. Full text: /usr/share/common-licenses/AGPL-3 or https://www.gnu.org/licenses/agpl-3.0.html
COPY
cat > "$ROOT/usr/bin/dave" << 'BIN'
#!/usr/bin/python3
import sys

from dave.cli import main

sys.exit(main())
BIN
chmod 755 "$ROOT/usr/bin/dave"
echo "/etc/default/dave" > "$ROOT/DEBIAN/conffiles"
cat > "$ROOT/DEBIAN/control" << CTRL
Package: dave
Version: $VERSION
Architecture: all
Maintainer: Dave maintainers <noreply@example.invalid>
Depends: python3 (>= 3.9), python3-yaml (>= 5.1)
Recommends: git, curl
Section: admin
Priority: optional
Homepage: https://github.com/dave-sec/dave
Description: security audit for self-hosted AI stacks
 Dave checks Ollama, OpenClaw, Open WebUI, Qdrant, n8n and friends for
 exposed ports, missing authentication, risky Docker settings, MCP client
 secrets and known vulnerable versions. 100% local, read-only by default.
CTRL
cat > "$ROOT/DEBIAN/postinst" << 'POST'
#!/bin/sh
set -e
mkdir -p /var/lib/dave/reports
chmod 750 /var/lib/dave
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
echo "Dave installé. Scan manuel : sudo dave scan /chemin/vers/compose --lang fr"
echo "Scan automatique chaque nuit : sudo systemctl enable --now dave-scan.timer"
exit 0
POST
cat > "$ROOT/DEBIAN/prerm" << 'PRE'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then systemctl disable --now dave-scan.timer >/dev/null 2>&1 || true; fi
exit 0
PRE
chmod 755 "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/prerm"
mkdir -p dist
dpkg-deb --root-owner-group --build "$ROOT" "dist/dave_${VERSION}_all.deb" >/dev/null
echo "dist/dave_${VERSION}_all.deb"
