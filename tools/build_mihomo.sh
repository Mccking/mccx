#!/usr/bin/env bash
# Builds the mihomo Android engine from source with the MccX patch applied.
#
#   tools/build_mihomo.sh                 # pinned version from MIHOMO_VER
#   MIHOMO_VER=v1.19.34 tools/build_mihomo.sh
#
# The stock release binary aborts TUN start with
#   "build android rules: read packages list: open /data/system/packages.xml: permission denied"
# because it tries to enumerate packages for per-app routing. See
# tools/patch_mihomo.py for the fix and why it is safe.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${MIHOMO_VER:-v1.19.33}"
OUT="${OUT:-$ROOT/libs/arm64-v8a/libmihomo.so}"
WORK="$ROOT/build/mihomo"

rm -rf "$WORK"
mkdir -p "$WORK" "$(dirname "$OUT")"

echo "== fetch mihomo $VERSION =="
curl -fsSL "https://codeload.github.com/MetaCubeX/mihomo/zip/refs/tags/${VERSION}" -o "$WORK/src.zip"
unzip -q "$WORK/src.zip" -d "$WORK"
SRC="$(find "$WORK" -maxdepth 1 -type d -name 'mihomo-*' | head -1)"
test -n "$SRC" || { echo "source tree not found" >&2; exit 1; }

echo "== patch =="
python3 "$ROOT/tools/patch_mihomo.py" "$SRC/listener/sing_tun/server_android.go"

echo "== build (android/arm64) =="
(
    cd "$SRC"
    GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
        go build -tags with_gvisor -trimpath \
        -ldflags "-s -w -X github.com/metacubex/mihomo/constant.Version=${VERSION#v}-mccx" \
        -o "$OUT" .
)

ls -l "$OUT"
echo "built $OUT"
