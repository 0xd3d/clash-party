#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_ROOT="${MIHOMO_CORE_ROOT:-$IOS_ROOT/../../modules/mihomo-ios-core}"

if [[ ! -d "$CORE_ROOT" ]]; then
  echo "mihomo-go-core not found at: $CORE_ROOT" >&2
  exit 1
fi

CORE_ROOT="$(cd "$CORE_ROOT" && pwd)"

BUILD_ROOT="${BUILD_ROOT:-$(mktemp -d /tmp/mihomo-mobile-build.XXXXXX)}"
GOCACHE_DIR="${GOCACHE_DIR:-/tmp/go-build}"
GOMODCACHE_DIR="${GOMODCACHE_DIR:-/tmp/gomodcache}"
GO_TOOLCHAIN="${GOTOOLCHAIN:-go1.20.14+auto}"
MIN_IOS_VERSION="${MIN_IOS_VERSION:-17.0}"
DEVICE_BUILD_TAGS="${DEVICE_BUILD_TAGS:-with_gvisor with_lwip}"
SIMULATOR_BUILD_TAGS="${SIMULATOR_BUILD_TAGS:-}"

OUTPUT_ROOT="$IOS_ROOT/Vendor"
FRAMEWORK_NAME="MihomoMobile"
ARCHIVE_BASE="$BUILD_ROOT/$FRAMEWORK_NAME"
HEADERS_DIR="$BUILD_ROOT/Headers"
DEVICE_ARCHIVE="$ARCHIVE_BASE.a"
SIMULATOR_ARCHIVE="$ARCHIVE_BASE-simulator.a"

mkdir -p "$BUILD_ROOT" "$HEADERS_DIR" "$OUTPUT_ROOT" "$GOCACHE_DIR" "$GOMODCACHE_DIR"

IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
IOS_CLANG="$(xcrun --sdk iphoneos --find clang)"
SIMULATOR_SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
SIMULATOR_CLANG="$(xcrun --sdk iphonesimulator --find clang)"

DEVICE_GO_ARGS=(
  build
  -trimpath
  -buildmode=c-archive
)

if [[ -n "$DEVICE_BUILD_TAGS" ]]; then
  DEVICE_GO_ARGS+=(-tags "$DEVICE_BUILD_TAGS")
fi

DEVICE_GO_ARGS+=(
  -o "$DEVICE_ARCHIVE"
  ./mobile/iosbridge
)

SIMULATOR_GO_ARGS=(
  build
  -trimpath
  -buildmode=c-archive
)

if [[ -n "$SIMULATOR_BUILD_TAGS" ]]; then
  SIMULATOR_GO_ARGS+=(-tags "$SIMULATOR_BUILD_TAGS")
fi

SIMULATOR_GO_ARGS+=(
  -o "$SIMULATOR_ARCHIVE"
  ./mobile/iosbridge
)

pushd "$CORE_ROOT" >/dev/null
env \
  GOCACHE="$GOCACHE_DIR" \
  GOMODCACHE="$GOMODCACHE_DIR" \
  GOTOOLCHAIN="$GO_TOOLCHAIN" \
  CGO_ENABLED=1 \
  GOOS=ios \
  GOARCH=arm64 \
  CC="$IOS_CLANG" \
  CGO_CFLAGS="-isysroot $IOS_SDK -arch arm64 -miphoneos-version-min=$MIN_IOS_VERSION" \
  CGO_LDFLAGS="-isysroot $IOS_SDK -arch arm64 -miphoneos-version-min=$MIN_IOS_VERSION" \
  go "${DEVICE_GO_ARGS[@]}"

# The simulator slice is only used for app-side debugging. Build it without
# gVisor/tun support so the app can run in Simulator even though Packet Tunnel
# paths stay device-only.
env \
  GOCACHE="$GOCACHE_DIR" \
  GOMODCACHE="$GOMODCACHE_DIR" \
  GOTOOLCHAIN="$GO_TOOLCHAIN" \
  CGO_ENABLED=1 \
  GOOS=ios \
  GOARCH=arm64 \
  CC="$SIMULATOR_CLANG" \
  CGO_CFLAGS="-isysroot $SIMULATOR_SDK -arch arm64 -target arm64-apple-ios$MIN_IOS_VERSION-simulator -mios-simulator-version-min=$MIN_IOS_VERSION" \
  CGO_LDFLAGS="-isysroot $SIMULATOR_SDK -arch arm64 -target arm64-apple-ios$MIN_IOS_VERSION-simulator -mios-simulator-version-min=$MIN_IOS_VERSION" \
  go "${SIMULATOR_GO_ARGS[@]}"
popd >/dev/null

cp "$BUILD_ROOT/$FRAMEWORK_NAME.h" "$HEADERS_DIR/$FRAMEWORK_NAME.h"
cat > "$HEADERS_DIR/module.modulemap" <<EOF
module $FRAMEWORK_NAME {
  header "$FRAMEWORK_NAME.h"
  export *
}
EOF

rm -rf "$OUTPUT_ROOT/$FRAMEWORK_NAME.xcframework"
xcodebuild -create-xcframework \
  -library "$DEVICE_ARCHIVE" \
  -headers "$HEADERS_DIR" \
  -library "$SIMULATOR_ARCHIVE" \
  -headers "$HEADERS_DIR" \
  -output "$OUTPUT_ROOT/$FRAMEWORK_NAME.xcframework"

echo "Built: $OUTPUT_ROOT/$FRAMEWORK_NAME.xcframework"
echo "Next: add the xcframework to ClashParty.xcodeproj and enable it for ClashParty + ClashPartyTunnel."
