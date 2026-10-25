#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_PATH="${PROJECT_PATH:-$IOS_ROOT/ClashParty.xcodeproj}"
SCHEME="${SCHEME:-ClashParty}"
CONFIGURATION="${CONFIGURATION:-Debug}"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-/tmp/clash-party-ios-derived-data-device}"
APP_NAME="${APP_NAME:-ClashParty}"
BUNDLE_IDENTIFIER="${BUNDLE_IDENTIFIER:-org.clashparty.ios}"
SKIP_MIHOMO_BUILD="${SKIP_MIHOMO_BUILD:-0}"
DEVICE_ID="${DEVICE_ID:-}"
ALLOW_PROVISIONING_UPDATES="${ALLOW_PROVISIONING_UPDATES:-1}"
ALLOW_PROVISIONING_DEVICE_REGISTRATION="${ALLOW_PROVISIONING_DEVICE_REGISTRATION:-1}"

resolve_first_connected_device_id() {
  xcrun xcdevice list 2>/dev/null | /usr/bin/python3 -c '
import json
import sys

try:
    devices = json.load(sys.stdin)
except Exception:
    devices = []

for device in devices:
    if device.get("simulator"):
        continue
    if not device.get("available", False):
        continue
    if device.get("platform") == "com.apple.platform.macosx":
        continue
    identifier = device.get("identifier", "").strip()
    if identifier:
        print(identifier)
        raise SystemExit(0)

raise SystemExit(1)
'
}

sanitize_extended_attributes_tree() {
  local target_path="$1"
  if [[ ! -e "$target_path" ]]; then
    return 0
  fi

  echo "Sanitizing extended attributes under: $target_path"
  /usr/bin/xattr -c "$target_path" 2>/dev/null || true
  /usr/bin/find "$target_path" -exec /usr/bin/xattr -c {} + 2>/dev/null || true
}

sanitize_codesign_inputs() {
  mkdir -p "$DERIVED_DATA_PATH"
  sanitize_extended_attributes_tree "$PROJECT_PATH"
  sanitize_extended_attributes_tree "$IOS_ROOT/Vendor"
  sanitize_extended_attributes_tree "$DERIVED_DATA_PATH"
}

if [[ -z "$DEVICE_ID" ]]; then
  if ! DEVICE_ID="$(resolve_first_connected_device_id)"; then
    echo "No connected iPhone or iPad was found." >&2
    echo "Connect and trust a physical iOS device, then re-run this script." >&2
    echo >&2
    echo "Currently visible devices:" >&2
    xcrun xcdevice list 2>/dev/null >&2 || true
    exit 1
  fi
fi

echo "Using device: $DEVICE_ID"

if [[ "$SKIP_MIHOMO_BUILD" != "1" ]]; then
  echo "Rebuilding MihomoMobile.xcframework..."
  "$SCRIPT_DIR/build-mihomo-mobile.sh"
fi

sanitize_codesign_inputs

echo "Building $SCHEME for device..."
XCODEBUILD_ARGS=(
  -project "$PROJECT_PATH" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination "id=$DEVICE_ID" \
  -derivedDataPath "$DERIVED_DATA_PATH" \
)

if [[ "$ALLOW_PROVISIONING_UPDATES" == "1" ]]; then
  XCODEBUILD_ARGS+=(-allowProvisioningUpdates)
fi

if [[ "$ALLOW_PROVISIONING_DEVICE_REGISTRATION" == "1" ]]; then
  XCODEBUILD_ARGS+=(-allowProvisioningDeviceRegistration)
fi

XCODEBUILD_ARGS+=(build)

xcodebuild "${XCODEBUILD_ARGS[@]}"

APP_PATH="$DERIVED_DATA_PATH/Build/Products/$CONFIGURATION-iphoneos/$APP_NAME.app"
if [[ ! -d "$APP_PATH" ]]; then
  echo "Built app bundle was not found at: $APP_PATH" >&2
  exit 1
fi

echo "Installing app onto device..."
xcrun devicectl device install app --device "$DEVICE_ID" "$APP_PATH"

echo "Launching app on device..."
xcrun devicectl device process launch --device "$DEVICE_ID" --terminate-existing "$BUNDLE_IDENTIFIER"

echo
echo "Build, install, and launch completed."
echo "Next step: open the app on the device and trigger the VPN path to continue runtime validation."
