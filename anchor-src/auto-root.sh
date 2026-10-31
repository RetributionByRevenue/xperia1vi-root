#!/usr/bin/env bash
# auto-root.sh — automatic re-root for Sony Xperia 1 VI (GhostLock, per-boot root)
#
# Root on this device does not survive a reboot (locked bootloader). This
# script re-establishes it: it waits for the phone, waits for boot to finish,
# runs the exploit, and verifies root. Leave it running before you reboot and
# root comes back by itself.
#
# Usage:   ./auto-root.sh [loop]
#   loop   keep watching forever (re-root after every reboot)
#
# Requires: adb (USB connected and authorized — the PC key stays authorized
# across reboots), ghostlock_native + xperia_profile_v4.bin already pushed
# to /data/local/tmp/ (see README.md).

set -u
SERIAL="${ADB_SERIAL:-}"
BIN=/data/local/tmp/ghostlock_native
PROF=/data/local/tmp/xperia_profile_v4.bin

adb_pick() { adb devices | awk 'NR>1 && $2=="device" {print $1; exit}'; }
adbsh()   { if [ -n "$SERIAL" ]; then adb -s "$SERIAL" shell "$@"; else adb shell "$@"; fi; }

one_round() {
    echo "[*] waiting for device..."
    if [ -n "$SERIAL" ]; then adb -s "$SERIAL" wait-for-device; else adb wait-for-device; fi

    echo "[*] waiting for boot to complete..."
    for _ in $(seq 1 90); do
        [ "$(adbsh getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
        sleep 2
    done
    sleep 5   # let the system settle (KernelSnitch likes a calm start)

    # already rooted?
    if adbsh "su -c id" 2>/dev/null | grep -q "uid=0"; then
        echo "[+] already rooted, nothing to do"
        return 0
    fi

    echo "[*] running exploit..."
    adbsh "$BIN --load-prebuilt-profile $PROF --force-attack" >/dev/null 2>&1

    if adbsh "su -c id" 2>/dev/null | grep -q "uid=0"; then
        echo "[+] ROOT re-established ✔"
        return 0
    fi
    echo "[-] missed this boot (~50% landing rate per attempt)"
    return 1
}

if [ "${1:-}" = "loop" ]; then
    echo "[*] auto-root loop started — leave this running; root returns after every reboot"
    misses=0
    while true; do
        if one_round; then misses=0; else misses=$((misses+1)); fi
        if [ "$misses" -ge 2 ]; then
            echo "[-] 2 consecutive misses — rebooting the phone and retrying"
            adbsh reboot >/dev/null 2>&1 || true
            misses=0
        fi
        sleep 20
    done
else
    if one_round; then exit 0; fi
    echo "hint: just reboot the phone and run this again (or use: ./auto-root.sh loop)"
    exit 1
fi
