# Sony Xperia 1 VI — One-Shot Root (GhostLock)

Root exploit for the **Sony Xperia 1 VI (XQ-EC72 / SOG13)** on kernel
`6.1.162-android14-11-g40b1a8089d75-ab14960999`, locked bootloader, using
GhostLock (CVE-2026-43499) via USB adb. No bootloader unlock, no flashing.

> **Disclaimer:** for use on your own device only. Rooting may void your
> warranty, trip DRM checks, and carries a real brick risk if you accept OTA
> updates afterwards. Provided as-is, no warranty.

## Files

| File | Purpose |
|---|---|
| `ghostlock_native` | The exploit binary (runs on the phone via adb shell) |
| `xperia_profile_v4.bin` | Device profile — kernel offsets, all values derived automatically from the kernel itself |
| `sample-success.log` | What a successful run looks like |
| `src/` | Complete exploit source code — build it yourself, study the mechanism |
| `anchor-src/` | Android app source for auto-root on boot (miniboot + Java app) |
| `full-writeup/` | The complete project history: pivots, confirmed findings, dead ends, the winning run |

> **Binary provenance:** `ghostlock_native` is derived from
> [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app) (Apache-2.0).
> The full source code is included in `src/` — see [`src/README.md`](src/README.md)
> for build instructions. This repo covers the **exploit chain only** — root is
> per-boot by the exploit's design.

## Requirements

- USB debugging enabled, adb working
- **ReSukiSU** app installed on the phone (`com.resukisu.resukisu`) — it supplies
  `libksud.so` and is the root-manager UI
- WiFi **off** (avoid OTA exposure)

## How it works (short)

1. **Leak** — KernelSnitch futex collision leaks a kernel `mm_struct` pointer →
   KASLR slide + a payload page in kernel memory.
2. **Race** — a pselect/futex PI-walk race reinterprets the payload page as
   rbtree + PI-waiter nodes (waiter = fd_buffer + 0x18, compact layout).
3. **W1** — rbtree erase trick writes `0` to `selinux_enforcing` (0x225A448) →
   SELinux permissive.
4. **W2** — same trick overwrites the child task's `cred` with `init_cred` →
   the child task runs as **uid 0**.
5. **Handoff** — the root script runs `ksud` (from ReSukiSU), which late-loads
   `kernelsu.ko` into the running kernel → persistent-for-this-boot KernelSU.

## Usage

Push and run (from the folder containing the files):

```bash
adb push ghostlock_native xperia_profile_v4.bin /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/ghostlock_native"
adb shell "/data/local/tmp/ghostlock_native --load-prebuilt-profile /data/local/tmp/xperia_profile_v4.bin --force-attack"
```

Success looks like:

```
[+] SELinux permissive
[+] child is root!
[+] KernelSU ready
```

Verify:

```bash
adb shell su -c id
# uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

## Important

- **Root is per-boot.** The kernel module lives in memory only; a reboot clears
  it. After every reboot, re-run the exploit command. Expect roughly a 50%
  landing rate per boot — if it exits without `[+] KernelSU ready`, just reboot
  and run it again (1–2 tries is normal; let the phone cool between attempts).
- Termux / other apps need a one-time grant in the ReSukiSU **Superuser** tab
  (adb shell is auto-trusted; normal apps are not). The grant also resets on
  reboot — re-grant after re-rooting.
- **Do not take OTA updates** while rooted, and keep WiFi off if you want to
  avoid them entirely. An OTA on a locked bootloader with kernel patching is a
  brick risk.
- A panic during a run is possible — the phone simply reboots; retry.

## Building from source

See [`src/README.md`](src/README.md) for build instructions and source layout.
Requires `aarch64-linux-gnu-gcc` (any recent cross-compiler). Includes device
offsets for 14 devices (Xperia 1 VI, OnePlus 13, Vivo X200 Ultra, and more).

## License

This project is provided for educational and research purposes. The exploit
source is derived from the GhostLock project (Apache-2.0). Use responsibly.
