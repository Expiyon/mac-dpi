#!/bin/bash
# dpi'yi bir LaunchAgent olarak kurar: her acilista arka planda calisir ve
# sistem proxy'sini otomatik ayarlar. Log: /tmp/dpi.log
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
PY="$(command -v python3 || echo /usr/bin/python3)"
LABEL="local.dpi"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>          <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PY</string>
        <string>$HERE/dpi.py</string>
        <string>run</string>
        <string>--set-proxy</string>
        <string>--quiet</string>
    </array>
    <key>RunAtLoad</key>      <true/>
    <key>KeepAlive</key>      <true/>
    <key>StandardOutPath</key><string>/tmp/dpi.log</string>
    <key>StandardErrorPath</key><string>/tmp/dpi.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
echo "Kuruldu: $PLIST"
echo "Log    : /tmp/dpi.log"
echo "Kaldir : ./uninstall-service.sh"
