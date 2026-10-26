# Source — build it yourself

Everything in this repo that touches the phone, with build instructions.

```
source/
├── miniboot.c        ← the on-device bootstrap client (single C file)
├── anchor/           ← the "Anchor" Android app (boot-time trigger)
│   ├── AndroidManifest.xml
│   ├── BootReceiver.java   ← BOOT_COMPLETED → spawns libminiboot.so
│   ├── MainActivity.java   ← launcher activity (un-stops the app on first open)
│   └── assets/             ← adbkey staged here at build time
└── build-apk.sh      ← one-shot build script
```

## What each piece does

**miniboot.c** — a minimal ADB client speaking the legacy TCP protocol
(`A_CNXN`/`A_AUTH` RSA-token handshake, SHA-1 signatures). It connects to the
phone's *own* adbd on `127.0.0.1:5555` (`persist.adb.tcp.port=5555`), which
gives it a **uid 2000 (shell)** context from inside an unprivileged app —
no USB, no PC, no root needed for the connection itself. Its `--autoroot`
mode: check `su -c id` → if not rooted, launch the exploit detached
(`setsid nohup`) → poll for root for ~3 minutes. Signing is done via
`dlopen("libcrypto.so")` (BoringSSL) — no bundled OpenSSL.

**Anchor app** — a tiny receiver-only APK. On `BOOT_COMPLETED` it stages the
adb private key from assets into `filesDir`, then execs
`nativeLibraryDir/libminiboot.so --autoroot`. That's the whole app.

**The exploit itself** (`ghostlock_native`) is the ghostlock-app community
core (YuKongA/ghostlock-app, CVE-2026-43499 lineage) — see that project for
its source; this repo ships the working binary + the Xperia profile. The
profile (`xperia_profile_v4.bin`) is generated from the kernel with their
`ghostlock-extract` tool — see `full-writeup/CONFIRMED-FINDINGS.md` for the
offsets.

## Building

```bash
# requirements: Android NDK (r25+), JDK 11+, python3, openssl, zip
./build-apk.sh            # → build/anchor.apk + build/adbkey(.pub)
./build-apk.sh install    # also installs and launches the app once
```

The script auto-downloads Android build-tools r34 and platform-34 into
`./sdk/` on first run (~130 MB from Google's CDN). Set `ANDROID_NDK` if your
NDK isn't at `~/Android/android-ndk-r27d`.

### Authorizing the key (once, needs root)

The APK embeds a fresh adb keypair. The public key must be trusted by adbd:

```bash
adb push build/adbkey.pub /data/local/tmp/
adb shell "su -c 'cat /data/local/tmp/adbkey.pub >> /data/misc/adb/adb_keys'"
```

This persists across reboots. From then on, at every boot: adbd listens on
TCP 5555 → Anchor runs miniboot → loopback adb → exploit → KernelSU root.

### Known Android gotchas

- A freshly installed app is in the **stopped state** and will NOT receive
  `BOOT_COMPLETED`. Launch the app once (manually, or `am start`) to arm it.
- `persist.adb.tcp.port=5555` must be set (needs root once):
  `adb shell "su -c 'resetprop persist.adb.tcp.port 5555'"`
- Executing the bundled binary works because it ships as a jniLib
  (`libminiboot.so` in `nativeLibraryDir`) — app *data* dirs are blocked for
  exec since Android 10, native lib dirs are not.

## The Termux alternative (no APK needed)

If you'd rather not build an APK, `ondevice/` contains the same logic as
Termux:Boot scripts (`root.sh`, `boot-autoroot.sh`) plus the prebuilt
`miniboot` binary — Termux:Boot replaces the Anchor app as the boot trigger.
The APK route is preferred: it's smaller, has no Termux update treadmill, and
survives Termux reinstalls.
