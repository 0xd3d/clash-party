#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEVICE_ID="${DEVICE_ID:-00008130-001241E13C2B803A}"
BUNDLE="${BUNDLE:-com.hubayi.clashpartyios}"
GUIDE="$ROOT/docs/shortcuts-app-automation.md"

if [[ ! -f "$GUIDE" ]]; then
  echo "Missing $GUIDE" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp "$GUIDE" "$TMP/ClashParty-快捷指令与自动化.md"

echo "Copying guide to device Files (App Documents)..."
xcrun devicectl device copy to \
  --device "$DEVICE_ID" \
  --domain-type appDataContainer \
  --domain-identifier "$BUNDLE" \
  --source "$TMP/ClashParty-快捷指令与自动化.md" \
  --destination "Documents/ClashParty-快捷指令与自动化.md"

echo "Done. On iPhone: Files → 我的 iPhone → Clash Party → Documents (or open Clash Party if exposed)."
echo "App Intents sync with the installed app; automations must still be created once in Shortcuts."