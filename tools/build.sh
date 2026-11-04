#!/usr/bin/env bash
# Linux/macOS build used by CI. The Windows equivalent is build.ps1; both run the
# same aapt2 -> javac -> d8 -> zip -> zipalign -> apksigner pipeline.
#
#   ANDROID_SDK_ROOT=/opt/android-sdk JAVA_HOME=/usr/lib/jvm/java-17 VERSION_CODE=42 VERSION_NAME=3.1.42 tools/build.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:?set ANDROID_SDK_ROOT or ANDROID_HOME}}"
BT="${BUILD_TOOLS:-$SDK/build-tools/35.0.0}"
AJAR="$SDK/platforms/android-34/android.jar"
JAVA_HOME="${JAVA_HOME:?set JAVA_HOME}"
VERSION_CODE="${VERSION_CODE:-8}"
VERSION_NAME="${VERSION_NAME:-3.1}"
APK_NAME="${APK_NAME:-mccx-${VERSION_NAME}.apk}"
KS_PATH="${KS_PATH:-$ROOT/keystore.jks}"
KS_PASS="${KS_PASS:-xehn-apk}"
KS_ALIAS="${KS_ALIAS:-xehn}"

BUILD="$ROOT/build"
DIST="$ROOT/dist"
LIB="$ROOT/lib"
JNI="$BUILD/aar/jni"

# Upstream XEHN engine (gomobile AAR): classes for dex, libgojni.so for the APK.
ENGINE_JAR=""
ENGINE_JNI=""
if [ -f "$LIB/engine.aar" ]; then
    rm -rf "$BUILD/engine-aar"
    mkdir -p "$BUILD/engine-aar"
    (cd "$BUILD/engine-aar" && unzip -oq "$LIB/engine.aar")
    ENGINE_JAR="$BUILD/engine-aar/classes.jar"
    ENGINE_JNI="$BUILD/engine-aar/jni"
fi
# A fresh clone has no extracted AAR: the WireGuard native libs live inside it.
if [ ! -d "$JNI/arm64-v8a" ]; then
    mkdir -p "$BUILD/aar"
    (cd "$BUILD/aar" && unzip -oq "$LIB/tunnel.aar")
fi
EXTRA_LIBS="$ROOT/libs"

rm -rf "$BUILD/gen" "$BUILD/classes" "$BUILD/dex" "$BUILD/stage"
mkdir -p "$BUILD/gen" "$BUILD/classes" "$BUILD/dex" "$BUILD/stage" "$DIST"

echo "== aapt2 =="
"$BT/aapt2" compile --dir "$ROOT/res" -o "$BUILD/res.zip"
"$BT/aapt2" link -o "$BUILD/base.apk" -I "$AJAR" \
    --manifest "$ROOT/AndroidManifest.xml" \
    --java "$BUILD/gen" \
    --min-sdk-version 24 --target-sdk-version 33 \
    --version-code "$VERSION_CODE" --version-name "$VERSION_NAME" \
    "$BUILD/res.zip"

echo "== javac =="
find "$ROOT/src" "$BUILD/gen" -name '*.java' > "$BUILD/sources.txt"
CP="$AJAR:$LIB/tunnel.jar:$LIB/collection.jar:$LIB/annotation.jar:$LIB/okhttp.jar:$LIB/okio.jar"
if [ -n "$ENGINE_JAR" ]; then CP="$CP:$ENGINE_JAR"; fi
"$JAVA_HOME/bin/javac" -encoding UTF-8 -source 8 -target 8 \
    -bootclasspath "$AJAR" -classpath "$CP" \
    -d "$BUILD/classes" "@$BUILD/sources.txt"

echo "== d8 =="
(cd "$BUILD/classes" && "$JAVA_HOME/bin/jar" cf "$BUILD/classes.jar" .)
"$BT/d8" --release --min-api 24 --lib "$AJAR" --output "$BUILD/dex" \
    "$BUILD/classes.jar" "$LIB/tunnel.jar" "$LIB/collection.jar" \
    "$LIB/annotation.jar" "$LIB/okhttp.jar" "$LIB/okio.jar" ${ENGINE_JAR:+"$ENGINE_JAR"}
test -f "$BUILD/dex/classes.dex"

echo "== package =="
cp "$BUILD/base.apk" "$BUILD/stage/app.apk"
cp "$BUILD/dex/classes.dex" "$BUILD/stage/classes.dex"
mkdir -p "$BUILD/stage/lib"
for abi in arm64-v8a armeabi-v7a; do
    if [ -d "$JNI/$abi" ]; then
        mkdir -p "$BUILD/stage/lib/$abi"
        cp "$JNI/$abi"/*.so "$BUILD/stage/lib/$abi/" 2>/dev/null || true
    fi
    if [ -d "$EXTRA_LIBS/$abi" ]; then
        mkdir -p "$BUILD/stage/lib/$abi"
        cp "$EXTRA_LIBS/$abi"/*.so "$BUILD/stage/lib/$abi/" 2>/dev/null || true
    fi
done
if [ -n "$ENGINE_JNI" ] && [ -f "$ENGINE_JNI/arm64-v8a/libgojni.so" ]; then
    cp "$ENGINE_JNI/arm64-v8a/libgojni.so" "$BUILD/stage/lib/arm64-v8a/"
fi
(cd "$BUILD/stage" && zip -qr app.apk classes.dex lib)

echo "== zipalign =="
"$BT/zipalign" -f -p 4 "$BUILD/stage/app.apk" "$BUILD/aligned.apk"

echo "== sign =="
if [ ! -f "$KS_PATH" ]; then
    echo "keystore 缺失: $KS_PATH（CI 里从 secrets 还原）" >&2
    exit 1
fi
"$BT/apksigner" sign --ks "$KS_PATH" --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
    --ks-key-alias "$KS_ALIAS" --v1-signing-enabled true --v2-signing-enabled true \
    --out "$DIST/$APK_NAME" "$BUILD/aligned.apk"

echo "== verify =="
"$BT/apksigner" verify --print-certs "$DIST/$APK_NAME"
"$BT/aapt2" dump badging "$DIST/$APK_NAME" | head -3

SHA="$(sha256sum "$DIST/$APK_NAME" | cut -d' ' -f1)"
SIZE="$(stat -c%s "$DIST/$APK_NAME" 2>/dev/null || stat -f%z "$DIST/$APK_NAME")"
echo "apk  $DIST/$APK_NAME  ($SIZE bytes)"
echo "sha256 $SHA"

# Manifest consumed by the app's self-update checker.
if [ -n "${APK_URL:-}" ]; then
    cat > "$DIST/update.json" <<EOF
{
  "versionCode": $VERSION_CODE,
  "versionName": "$VERSION_NAME",
  "url": "$APK_URL",
  "sha256": "$SHA",
  "notes": "${NOTES:-}"
}
EOF
    echo "manifest $DIST/update.json"
fi


