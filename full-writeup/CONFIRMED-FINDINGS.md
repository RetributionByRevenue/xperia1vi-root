# Confirmed Findings — Xperia 1 VI (XQ-EC72 / SOG13)

Everything below was verified on-device, in the QEMU VM running the identical
kernel image, or by static analysis (BTF, disassembly, kallsyms) of
`6.1.162-android14-11-g40b1a8089d75-ab14960999`.

## Kernel address map

| Constant | Value | How confirmed |
|---|---|---|
| KIMAGE_TEXT_BASE | `0xffffffc008000000` | kernel image analysis |
| KASLR slide (one observed boot) | `0x133a400000` | panic `Kernel Offset:` line |
| kernel_phys_load | `0xa8000000` | extractor (Sony loader placement) |
| PHYS_OFFSET (DRAM base) | `0x80000000` | device DT |
| Linear map alias formula | `0xffffff8028000000 + off` for kernel-image data | init_cred alias `0xffffff802a0318e8` = base + 0x20318E8, exact |

## Symbol offsets (ground truth: `ghostlock-extract --format json`)

| Symbol | Offset | Decimal |
|---|---|---|
| init_task | `0x201F440` | 33682496 |
| init_cred | `0x20318E8` | 33757416 |
| root_task_group | `0x2207xxx` | 35689856 |
| **selinux_enforcing** | **`0x225A448`** | **36021320** |
| selinux_blob_sizes | `0x15D0768` | 22874664 |
| security_hook_heads | `0x15Dxxxx` | 22878584 |
| ashmem_misc_fops | `0x217CC70` | kallsyms |
| slide_nfulnl_logger | `0x20127D0` | 33630160 |
| slide_loggers_0_1 | `0x20127D0`-16 | 33629984 |
| slide_boot_id | `0x227A4D8` | 36156632 |

⚠ `selinux_enforcing = 0x225B448` (+0x1000) appears in stale/hand-written
profiles — that typo cost an entire night. Always take these from the
extractor JSON.

## task_struct (BTF-verified)

prio 0x84 · normal_prio 0x8c · sched_task_group 0x348 · tasks 0x550 ·
pid 0x630 · tgid 0x634 · atomic_flags 0x5f0 · real_cred 0x830 · cred 0x838 ·
comm 0x848 · seccomp 0x900 · pi_lock 0x924 · pi_waiters 0x938 ·
pi_top_task 0x948 · **pi_blocked_on 0x950** (an older target.h said 0xA18 — stale)

`mm_struct`: true size = **960 (0x3C0)**, but the KernelSnitch algorithm
parameter `mm_struct_sz` must be **1024**. These are different things.

## Pselect/futex geometry (canary-measured)

| Quantity | Value |
|---|---|
| pselect frames | 0x90 / 0x1c0, stack_fds @ sp+0x50 |
| futex frames | 0x70 / 0x60 / 0x1b0, waiter @ sp+0x98 |
| **waiter − fd_buffer** | **+0x18** (D=0x18, shift=3 in our table ≡ shift 1 in ghostlock-app's) |
| Compact overlay words | 2/5 = tree_pc/pi_pc (write parent), 3/6 = right, 4/7 = left (write target), 8 = fake_task, 9 = fake_lock, 10 = `(prio<<32)\|3` wake_prio |

Independently confirmed by the ghostlock-app extractor ("derived 3 − 2").

## The write primitive (rbtree-erase trick)

The PI-walk's rbtree unlink performs `child->__rb_parent_color = node->pc` on
single-child erase. Authoring the overlay so the erase's child = the target
and the node's pc = the write value turns the walk into an arbitrary 8-byte
write. W1 (value 0, target `selinux_enforcing`) and W2 (value/parent layout
overwriting `cred` with `init_cred`) both landed on-device with this.

## Failure modes (device)

| Signature | Meaning |
|---|---|
| trylock fault at `0x25` (device) / `0x0` (VM) | reclaim **miss** — the walk consumed a dirty/zeroed stale frame. Discard and retry. |
| Set-1 landed crash `0x339`, `x27 = 0x301` | page leftmost red-tagged pre-walk; value-dependent; topology-independent; writer never caught. Unsolved — and moot after the profile fix. |
| "Clean race, no effect" | the write landed at a **wrong address** — audit target arithmetic. |
| tcp_zerocopy trylock on `page+0xe80` | garbage page_base; route needs its own tuning on this device. Do not use. |

## Reliability numbers

- ~50% reclaim-landing rate per boot; cold streaks correlate with thermal state
- Winning profile: W1 landed on **attempt 1**, full chain ~12 s
- Panics during attempts are benign: the phone reboots, retry

## Dead ends (do not revisit without new evidence)

1. configfs/physrw write-verification chain — structurally broken on this
   kernel (fields beyond 64-byte ashmem name reach; no ENOTTY path in handler;
   FMODE_CAN_WRITE never set).
2. Shizuku — unnecessary (adb shell = uid 2000); v13.6 manager no longer embeds
   the server dex; app_process server start dies with ClassNotFoundException.
3. All four Set-1 overlay topologies (empty-tree, black-root W0, fops-parent,
   target−8) — identical crashes on landed runs.
4. tcp_zerocopy route on this device — panics, needs its own profile tuning.
5. `mm_struct_sz = 960` — breaks the KernelSnitch leak (accepts garbage).

## Post-exploit state

- `su -c id` → `uid=0(root) ... context=u:r:ksu:s0`; SELinux back to Enforcing
  (ksud policy fixup, policyload 0→2)
- ksud 4.2.0-rc3 at `/data/adb/ksud`; ReSukiSU manager = grant UI; adb shell
  auto-trusted, normal apps (e.g. Termux, uid 10454) need a manual grant
- Root is **per-boot**; re-run the exploit after each reboot
