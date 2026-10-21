#!/usr/bin/env bash
# brand_apk_on_mac.sh -- run BEFORE scripts/build_launcher.sh.
# Replaces the upstream Mac.apk icon master with one rendered from
# images/apk-on-mac-logo.svg (TRADEMARKS.md: no distribution under the Mac.apk
# icon). build_launcher.sh derives AppIcon.icns and the default Dock icon from
# images/mac_apk_icon_512.png. Names (CFBundleName, window title, DMG name and
# volume, .app name inside the DMG) are set in source / build_dist.sh env vars.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v rsvg-convert >/dev/null || brew install librsvg
rsvg-convert -w 512 -h 512 "$ROOT/images/apk-on-mac-logo.svg" -o "$ROOT/images/mac_apk_icon_512.png"
echo "branded icon master written: images/mac_apk_icon_512.png"
