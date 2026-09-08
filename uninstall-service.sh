#!/bin/bash
# LaunchAgent'i kaldirir ve sistem proxy'sini eski haline dondurur.
HERE="$(cd "$(dirname "$0")" && pwd)"
LABEL="local.dpi"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

launchctl unload "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
python3 "$HERE/dpi.py" restore || true
echo "Kaldirildi."
