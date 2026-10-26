# Set 2 — THEIR exploit (YuKongA/ghostlock-app evolved core)

The community GhostLock app: the same CVE-2026-43499 lineage restructured into
C++ with a profile system, per-kernel device profiles for 90+ kernels, an
evolved stage chain (W1 → W2 → W3 seccomp bypass → ksud handoff), and an extra
route (tcp_zerocopy) that avoids the pselect stack geometry entirely.

- `ghostlock-app/` — the full repo (their core = `src/core/`, the profile
  docs = `docs/kernel_profiles/`, the offset extractor =
  `tools/extract_rs`, the prebuilt native binary at
  `build/extract/release/ghostlock-extract` … note: the *exploit* binary is
  the GitHub pre-release asset `ghostlock`)
- `profile/xperia_profile.conf` — the HOCON profile generated from OUR kernel
- `profile/xperia_profile.bin` — the same, compiled to their v2 binary format

Phone paths: `/data/local/tmp/ghostlock_native` (their core),
`/data/local/tmp/xperia_profile.bin` (our profile).

## Why this set matters

Their core is the community-validated implementation for this exact kernel
family (6.1.162-android14, SM8650 sibling device: Zenfone 11 Ultra). Our Set-1
crash (`0x339`, the red-tagged self-referential page pointer) may not exist in
their implementation — different authoring, different stage policy.

## The pipeline (built and working end-to-end)

1. **Extract** the profile from our kernel:
   ```
   ghostlock-extract analysis/kernel --kallsyms kallsyms_std.txt \
       --phys 0xa8000000 --format conf --out xperia_profile.conf
   ```
   (kallsyms must be standard `T/D` format; ours needed conversion from
   `FUNC/OBJECT`. The extractor independently derived our pselect geometry:
   frames match our disassembly, "derived 3 − 2" = shift 1 in their table
   convention ≡ shift 3 in ours.)
2. **Compile** the HOCON to their v2 binary profile format:
   * magic `0x0D000721`, u16 version = 2, u16 frontend = 1 (RootChild),
     u16 backend = 1 (CVE-2026-43499), u16 middleware = 2 (SelectStack),
     u16 release_len, **2 pad bytes**, release string, u16 section_count,
     then sections: u8 name_len, name, u32 entry_count,
     {u8 key_len, key, u64 value}…
   * Serializer script: in this session's history (`mkprofile` inline python);
     artifact = `profile/xperia_profile.bin`
3. **Run** on the phone (adb shell = uid 2000, no Shizuku needed):
   ```
   /data/local/tmp/ghostlock_native \
       --load-prebuilt-profile /data/local/tmp/xperia_profile.bin \
       --force-attack
   ```

## Profile notes for this kernel

* `kernel_phys_load = 0xA8000000`, `kernel_phys_offset = 0x80000000`
  (the extractor writes 0 for the offset — fix it; the Sony DRAM base)
* task_struct: all fields match our BTF including
  `pi_blocked_on = 2384 (0x950)` — our Set-1 target.h `0xA18` was stale
* `route = select_stack`, `waiter_shift = 1` (their table convention)
* **Every `execution.*` section must be present** — absent keys read as 0
  (zero attempts ⇒ instant "Write 1 failed"). Defaults:
  `execution-tuning.conf` (w1=15, w2=15, w3=3×6, heap=4 attempts/240s,
  race 1s/300s, handoff) + `execution-select-stack.conf`
  (enter_delay 50ms, timeout 200ms, consumer 1×1)

## Status / first-run results

* Profile loads: `resolved profile loaded: 6.1.162-android14-11-g40b1a…` ✓
* The attack chain runs: leak ✓ spray ✓ races complete **cleanly**
  (`status=0 clean=1/1`) — no `0x339`, no freezes, the phone stays alive
* W1 (SELinux): 15/15 races completed but SELinux stayed enforcing — the W1's
  leaf/parent write needs reconciliation with their exact value semantics
  (their `payload_write_layout`: `layout.parent = target − 8`, W1 = leaf ⇒ the
  erase writes `[target] = NULL` through `parent->rb_right`)
* **First full-run ended in `kernel_panic,null`** — the ramoops shows
  `trylock` fault at `0x25` (the same stale-frame miss class as Set 1; the
  panic hit during a later stage/attempt, not a new mechanism)
* Next: rerun (the miss rate is ~50%), and if W1 keeps missing the *value*,
  diff their `payload_builder`/leaf semantics against our authoring and port
  the W1 value fix into their core

## Their route catalog (for reference)

* `route/select_stack_route.cpp` — the pselect/select() race (our Set-1
  equivalent, restructured; compact table: task@word8, lock@word9, wake_prio
  packed `(140<<32)|3` at word 10, tree_pc/pi_pc = the write parent,
  tree_left/pi_left = the write target)
* `route/tcp_zerocopy_route.cpp` — the TCP punch race (their PRIMARY for
  6.1.162; sidesteps the pselect stack geometry entirely)
* `route/multicast_waiter_route.cpp` — a third variant

## SESSION 12 — ROOT ACHIEVED (2026-10-27 ~02:40)

**Winning run:** `ghostlock_native --load-prebuilt-profile /data/local/tmp/xperia_profile_v4.bin --force-attack` (select_stack route).

```
W1: SELinux OFF ✅  →  W2: child uid = 0 ✅  →  W3 skipped (no app seccomp)
handoff: ksud 4.2.0-rc3 late-load kmi=android14-6.1 exit=0
KernelSU module loaded ✅  →  su -c id = uid=0 context=u:r:ksu:s0
SELinux back to Enforcing (ksud policy fixup, policyload 0→2)
```

**The two profile bugs that blocked W1 all night (both mine, both transcription):**
1. `selinux_enforcing = 0x225B448` in my hand-built conf — the true value is **0x225A448** (36021320). +0x1000 typo ⇒ W1 zeroed the wrong address 15×, races "clean" but SELinux untouched.
2. `selinux_blob_sizes` = the Zenfone's value, not ours.

**The fix that ended it:** generate the profile **entirely from `ghostlock-extract --format json`** (`profile/xperia_extracted.json` → `profile/xperia_profile_v4.bin`). No hand-entered numbers. First run with it: W1 landed, root.

**Post-state:** root is per-boot (kernelsu.ko lives in memory; locked bootloader persists nothing kernel-side). Re-run per boot:
`adb shell "/data/local/tmp/ghostlock_native --load-prebuilt-profile /data/local/tmp/xperia_profile_v4.bin --force-attack"`
(~50% landing rate; retry fresh boots until the W1 flip.)

**Dead ends recorded this session:** tcp_zerocopy route panics on this device (trylock on page+0xe80 of a garbage page_base — needs its own tuning, don't use); `mm_struct_sz=960` breaks the KernelSnitch leak (accepts garbage `0xf9ffff81...`) — 1024 is the algorithm parameter (960 is only the true struct size, informational).
