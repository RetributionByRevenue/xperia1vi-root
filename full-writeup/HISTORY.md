# History — how the root actually happened

## Phase 0 — Setup and constraints

- **Target:** Sony Xperia 1 VI (XQ-EC72, docomo SOG13), SM8650, kernel
  `6.1.162-android14-11-g40b1a8089d75-ab14960999`, **locked bootloader**.
- **Method:** GhostLock (CVE-2026-43499) — a futex/pselect PI-walk type
  confusion that yields arbitrary kernel writes from adb shell (uid 2000).
- **User constraints:** USB adb only (no WiFi — fear of OTA updates), exploit
  work organized into two Desktop folders (one per exploit set).
- **Environment quirk that shaped everything:** a QEMU VM ran the *same*
  kernel image. The VM had no KASLR pressure, no memory pressure, and clean
  stale frames — behavior there never matched the device. Learning to tell
  "VM truth" from "device truth" was half the battle.

## Phase 1 — Set 1: our own C exploit (~50 device boots)

Adapted the `ghostlock-oneplus` C exploit to the Xperia. The reliable parts came
up fast: KernelSnitch mm_struct leak, heap spray, futex collisions, and the
race itself — the walk *did* consume our overlay and complete on-device.

The blocker was a hard crash on every **landed** run:

```
Unable to handle kernel paging request at virtual address 0x339
pc : adjust_prio_chain+0x1ec   x27 = 0x301
```

`0x301` decoded as our page's leftmost rbtree pointer (`W0_OFFSET`) red-tagged
(`|1`). The debugging campaign that followed produced the project's most
valuable measurement technique:

- **FD canaries** — authoring overlay words as `0xAAAA0000+g` made the panic
  address name the exact word the walk consumed → measured
  **waiter = fd_buffer + 0x18** (shift 3 in our table convention).
- **Page canaries** (`0xBBBB000x`) proved the authored leftmost pointer was
  consumed intact — the tagging happened between authoring and read.
- **Register dumps** pinned the faulting block to `[lock+0x10]` then
  `[x27+0x38]`.

Four overlay topologies were A/B tested across sweep devloop2/4/5/6/8/9
(empty tree, black-root W0, fops-table parent, target−8 parent): **all crashed
identically on landed runs.** The corruption was pre-walk, value-dependent,
and its writer was never caught by any canary. Set 1 was parked — with its
canary method kept as the project's measurement microscope.

**Dead ends closed in this phase:**

- *configfs/physrw write-verification chain* — structurally impossible on this
  kernel: the confused `configfs_buffer` fields sit beyond the 64-byte ashmem
  name reach; the ENOTTY happens in the VFS before the handler; FMODE_CAN_WRITE
  is never set because `misc_open` swaps `f_op` after `do_dentry_open`.
- *Shizuku* — unnecessary (adb shell is already uid 2000) and its v13.6 manager
  APK no longer embeds the server dex.
- *Set-1 target.h* — `pi_blocked_on = 0xA18` was stale; BTF says **0x950**
  (harmless with zero-fill, but a warning sign about hand-maintained offsets).

## Phase 2 — The pivot to Set 2 (ghostlock-app)

The community GhostLock app (YuKongA/ghostlock-app) is the same CVE restructured
into C++ with a profile system, an evolved stage chain (W1 → W2 → W3 → ksud
handoff), and a second route (tcp_zerocopy). We mined the repo, built its
offset extractor, and ran it on our kernel — it **independently confirmed** the
canary-measured geometry ("derived 3 − 2") and produced a full device profile.

The pipeline took real engineering:

- kallsyms had to be converted to standard `T/D` format for the extractor.
- The profile serializer (v2 binary format: magic `0x0D000721`, 16-byte header
  with 2 pad bytes, typed sections) was written by hand — **this later became
  the source of the winning bug hunt.**
- Two profile bugs were fixed along the way: `kernel_phys_offset` written as 0
  by the extractor (correct: `0x80000000`), and absent `execution.*` keys
  reading as 0 (zero attempts ⇒ instant "Write 1 failed").

Set 2 ran on the phone with no Set-2-specific crashes — races completed
**cleanly** (`status=0 clean=1/1`) — but W1 never flipped SELinux. 15/15
attempts: clean races, enforcing SELinux. A genuinely confusing state: with a
miss, the walk consumes a dirty stale frame and panics (trylock `0x25`) — but
there were no panics.

## Phase 3 — The false lead and the whiplash

Convinced the failures were page reclamation under memory pressure (anon pages
getting swapped out between spray and walk), we pivoted to their **tcp_zerocopy**
route — MSG_ZEROCOPY pins payload pages with skb references. It crashed with a
*new* signature: a trylock on `page+0xe80` of a leaked page_base that decoded
to a **non-existent physical page**.

The diagnosis was wrong twice before it was right:

1. First guess: `mm_struct_sz` should be 960 (the true struct size from BTF) —
   setting that **broke the KernelSnitch leak** (it accepted garbage
   `0xf9ffff81...`). Reverted: **1024 is the algorithm's parameter**, 960 is
   only the struct size.
2. The tcp_zerocopy crash was real but its lesson was narrow: that route needs
   its own profile tuning on this device. Dead end, don't revisit.

## Phase 4 — The actual breakthrough: audit every hand-entered number

While cross-checking the crash, a mismatch surfaced in the logs: the printed
W1 target was `0xffffff802a25b448`, but `physmap_base + 0x225A448` =
`0xffffff802a25a448`. A **+0x1000 difference**. Python confirmed it:

- My hand-built profile had `selinux_enforcing = 36025416` = `0x225B448` —
  a transcription typo. The true offset is **0x225A448** (36021320).
- The profile's `selinux_blob_sizes` was the **Zenfone's** value, not ours.

That meant W1 had been zeroing the wrong address 15 times per run — races
"clean" (the write landed, just nowhere harmful), SELinux untouched. The
exploit had probably been *working* the entire time.

**The fix was structural, not just numeric:** regenerate the profile entirely
from `ghostlock-extract --format json` — zero hand-entered numbers. The v4
profile was compiled programmatically from `xperia_extracted.json`.

## Phase 5 — ROOT

First run of the v4 profile:

```
W1: SELinux OFF (attempt 1/15)  →  W2: child uid = 0  →  W3 skipped (no app seccomp)
handoff: ksud 4.2.0-rc3 late-load kmi=android14-6.1 exit=0
[+] KernelSU module loaded          →  su -c id = uid=0 context=u:r:ksu:s0
```

SELinux was restored to **Enforcing** by ksud's policy fixup after the exploit
window — a clean end state. Root is per-boot (locked bootloader persists
nothing kernel-side); re-running the exploit after each reboot works, at
roughly a 50% landing rate.

## Lessons learned

1. **Never hand-transcribe numbers into a config.** Both winning bugs were
   transcription errors, and they survived many otherwise-correct runs. The
   extractor JSON → binary profile pipeline (no human in the loop) is what
   actually fixed the exploit.
2. **"Clean race but no effect" means the write landed somewhere else** — check
   the target address arithmetic before questioning the mechanism.
3. **Per-boot artifacts vs. algorithm parameters:** `mm_struct_sz = 1024`
   (algorithm) vs 960 (struct size) — a value can be "wrong" and still required.
4. **The VM is not the device.** VM behavior validated the mechanism; only
   device runs could validate the profile.
5. **A crash you can't reproduce after a profile fix may have been the profile
   all along** — the Set-1 `0x339` mystery remains unsolved and *may* be the
   same class of authoring error; we never needed to find out.
