#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UDID="${DEVICE_ID:-00008130-001241E13C2B803A}"
BUNDLE="${BUNDLE_IDENTIFIER:-com.hubayi.clashpartyios}"
OUTPUT_NAME="${OUTPUT_NAME:-ios-latency-benchmark.json}"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-/tmp/clash-party-ios-derived-data-device}"
COLD="${COLD:-1}"
PULL_DIR="${PULL_DIR:-$IOS_ROOT/../../.ios-benchmark-$(date +%Y%m%d%H%M%S)}"

mkdir -p "$PULL_DIR"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "Building and installing Debug on device..."
  set +e
  SKIP_MIHOMO_BUILD="${SKIP_MIHOMO_BUILD:-1}" \
    DEVICE_ID="$UDID" \
    "$SCRIPT_DIR/build-install-run-device.sh"
  build_status=$?
  set -e
  if [[ "$build_status" != "0" ]]; then
    echo "Note: install script exit $build_status (launch after install may fail until the dev cert is trusted on device)."
  fi
fi

LAUNCH_ARGS=(--codex-latency-benchmark)
if [[ "$COLD" == "1" ]]; then
  LAUNCH_ARGS+=(--codex-latency-cold)
fi

TRIGGER="trigger-ios-latency-benchmark"
if [[ "$COLD" == "1" ]]; then
  TRIGGER="trigger-ios-latency-cold"
fi
touch "/tmp/$TRIGGER"
xcrun devicectl device copy to --device "$UDID" \
  --domain-type appDataContainer \
  --domain-identifier "$BUNDLE" \
  --destination "Documents/$TRIGGER" \
  --source "/tmp/$TRIGGER" \
  --user mobile 2>/dev/null || true

echo "Launching benchmark on $UDID (keep iPhone unlocked)..."
set +e
xcrun devicectl device process launch --device "$UDID" --terminate-existing "$BUNDLE" -- "${LAUNCH_ARGS[@]}"
launch_status=$?
set -e
if [[ "$launch_status" != "0" ]]; then
  echo
  echo "Automated launch was blocked (trust / lock screen)."
  echo "On the iPhone: unlock → open Clash Party once (Documents/$TRIGGER is already in place)."
  echo "The benchmark runs automatically on that open and writes Documents/$OUTPUT_NAME."
  echo
fi

echo "Waiting for $OUTPUT_NAME on device..."
deadline=$((SECONDS + 180))
while (( SECONDS < deadline )); do
  if xcrun devicectl device copy from --device "$UDID" \
    --domain-type appDataContainer \
    --domain-identifier "$BUNDLE" \
  --source "Documents/$OUTPUT_NAME" \
    --destination "$PULL_DIR/$OUTPUT_NAME" 2>/dev/null; then
    if [[ -s "$PULL_DIR/$OUTPUT_NAME" ]]; then
      echo
      echo "Benchmark written to: $PULL_DIR/$OUTPUT_NAME"
      cat "$PULL_DIR/$OUTPUT_NAME"
      exit 0
    fi
  fi
  sleep 3
done

echo "Timed out waiting for benchmark output." >&2
exit 1