#!/usr/bin/env bash
# build-apk.sh — build the GhostLock Anchor APK from source.
#
# Produces:   build/anchor.apk  (signed, ready for `adb install`)
#             build/adbkey      (dedicated adb RSA private key, embedded in the APK)
#             build/adbkey.pub  (adb-format public key — authorize it ONCE with root:
#                                `cat build/adbkey.pub >> /data/misc/adb/adb_keys`
#                                as root on the phone; persists across reboots)
#
# Requirements:
#   - Android NDK (r25+), JDK 11+ (keytool/javac)
#   - Android build-tools (aapt2, d8, apksigner, zipalign) and android.jar
#     The script auto-downloads them into ./sdk/ if missing (~130 MB, Google's CDN).
#   - Target device profile: the exploit binary + profile at
#     /data/local/tmp/{ghostlock_native,xperia_profile_v4.bin} on the phone.
#
# Usage:  ./build-apk.sh            # build
#         ./build-apk.sh install    # build + adb install + launch once (un-stops the app)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BT=""
AJ=""

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# 1. toolchain
# ---------------------------------------------------------------------------
NDK="${ANDROID_NDK:-$HOME/Android/android-ndk-r27d}"
CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang"
[ -x "$CLANG" ] || { echo "ERROR: NDK clang not found at $CLANG (set ANDROID_NDK)"; exit 1; }
have javac || { echo "ERROR: javac not found (install a JDK)"; exit 1; }

SDKDIR="$HERE/sdk"
if [ -z "${ANDROID_BT:-}" ]; then
  if [ -x "$SDKDIR/android-14/aapt2" ]; then
    BT="$SDKDIR/android-14"
  else
    echo "[*] downloading Android build-tools r34 + platform 34 (~130 MB)..."
    mkdir -p "$SDKDIR" && cd "$SDKDIR"
    curl -sL -o bt.zip   "https://dl.google.com/android/repository/build-tools_r34-linux.zip"
    curl -sL -o plat.zip "https://dl.google.com/android/repository/platform-34-ext7_r03.zip"
    unzip -q bt.zip && unzip -q -o plat.zip -d plat
    BT="$SDKDIR/android-14"
    cd "$HERE"
  fi
else
  BT="$ANDROID_BT"
fi
[ -f "$SDKDIR/plat/android-34/android.jar" ] || { echo "ERROR: android.jar missing"; exit 1; }
AJ="$SDKDIR/plat/android-34/android.jar"

# ---------------------------------------------------------------------------
# 2. dedicated adb keypair (fresh on every clean build)
# ---------------------------------------------------------------------------
mkdir -p "$HERE/build"
if [ ! -f "$HERE/build/adbkey" ]; then
  echo "[*] generating dedicated adb keypair..."
  openssl genrsa -out "$HERE/build/adbkey" 2048 2>/dev/null
  python3 - "$HERE/build/adbkey" "$HERE/build/adbkey.pub" <<'EOF'
import base64, subprocess, sys
pem, out = sys.argv[1], sys.argv[2]
mod = subprocess.check_output(['openssl','rsa','-in',pem,'-noout','-modulus']).decode()
n = int(mod.strip().split('=')[1], 16)
e = 65537
def enc(v):
    b = v.to_bytes((v.bit_length()+7)//8, 'little')
    w = (len(b)+3)//4
    return w.to_bytes(4,'little') + b.ljust(w*4, b'\x00')
pub = enc(n) + enc(e)
open(out,'wb').write(base64.b64encode(pub) + b' ghostlock-anchor\n')
EOF
  echo "[!] authorize build/adbkey.pub ON THE PHONE (root):"
  echo "    cat adbkey.pub >> /data/misc/adb/adb_keys"
fi

# ---------------------------------------------------------------------------
# 3. native binary -> jniLib (executed from nativeLibraryDir at boot)
# ---------------------------------------------------------------------------
echo "[*] compiling miniboot (aarch64)..."
mkdir -p "$HERE/anchor/jni"
"$CLANG" "$HERE/miniboot.c" -O2 -o "$HERE/anchor/jni/libminiboot.so" -ldl

# ---------------------------------------------------------------------------
# 4. APK: dex + resources + native lib + key asset, align, sign
# ---------------------------------------------------------------------------
echo "[*] building APK..."
rm -rf "$HERE/build/classes" "$HERE/build/dex"
mkdir -p "$HERE/build/classes" "$HERE/build/dex"
javac -source 8 -target 8 -bootclasspath "$AJ" -classpath "$AJ" \
      -d "$HERE/build/classes" "$HERE"/anchor/*.java 2>&1 | grep -vi warning || true
"$BT/d8" --release --lib "$AJ" --output "$HERE/build/dex" \
         $(find "$HERE/build/classes" -name '*.class')

"$BT/aapt2" link -I "$AJ" \
    --manifest "$HERE/anchor/AndroidManifest.xml" \
    -A "$HERE/anchor/assets" \
    -o "$HERE/build/base.apk" --auto-add-overlay

cp "$HERE/build/adbkey" "$HERE/anchor/assets/adbkey" 2>/dev/null || true
# rebuild apk including the staged key asset
"$BT/aapt2" link -I "$AJ" \
    --manifest "$HERE/anchor/AndroidManifest.xml" \
    -A "$HERE/anchor/assets" \
    -o "$HERE/build/base.apk" --auto-add-overlay

cd "$HERE/build"
cp dex/classes.dex . && zip -qj base.apk classes.dex
mkdir -p lib/arm64-v8a && cp ../anchor/jni/libminiboot.so lib/arm64-v8a/
zip -qr base.apk lib
cd "$HERE"

"$BT/zipalign" -f 4 build/base.apk build/aligned.apk
[ -f build/debug.keystore ] || keytool -genkeypair -keystore build/debug.keystore \
    -alias anchor -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass android -keypass android -dname "CN=anchor" >/dev/null 2>&1
"$BT/apksigner" sign --ks build/debug.keystore --ks-pass pass:android \
    --ks-key-alias anchor --out build/anchor.apk build/aligned.apk

echo "[+] built build/anchor.apk"

# ---------------------------------------------------------------------------
# 5. optional install
# ---------------------------------------------------------------------------
if [ "${1:-}" = "install" ]; then
  adb uninstall com.ghostlock.anchor >/dev/null 2>&1 || true
  adb install build/anchor.apk
  # launching once clears Android's "stopped" state so BOOT_COMPLETED is delivered
  adb shell "am start -n com.ghostlock.anchor/.MainActivity" || \
    echo "[!] am start blocked (stopped state) — open the app once on the phone"
  echo "[i] then reboot the phone: the anchor re-roots automatically"
fi
