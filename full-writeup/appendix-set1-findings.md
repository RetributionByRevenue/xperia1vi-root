# Set 1 — OUR exploit (ghostlock-oneplus, Xperia-adapted)

The C exploit we adapted and debugged for the Xperia 1 VI across ~50 device
boots. This folder = the complete working tree + the built binary + the kernel
analysis artifacts.

- `exploit/` — the full tree: `src/` (the exploit), `analysis/` (kernel Image,
  vmlinux, kallsyms), the built `ghostlock` binary, `devices/xperia1vi/`
  (our offsets/profile)
- Phone path: `/data/local/tmp/ghostlock` (run: `env PSELECT_SHIFT=3
  ./ghostlock --force-umh`)

## What works

* KernelSnitch mm leak, heap spray, futex collisions — reliable
* The race itself: the walk consumes our overlay, completes, and performs the
  unlink write — **proven on-device** (`post-select ret=4 success=1`)
* The vm_init offsets for this exact kernel (BTF-verified; see
  `exploit/devices/xperia1vi/offsets.h`)

## The blocker (measured, not guessed)

**Geometry (canary-proven):** the walk consumes the overlay with
`waiter = fd_buffer + 0x18` — the `lock` field from global fd word 10
(canary fault `0xAAAA000A` at the trylock). Independently confirmed by the
ghostlock-app extractor ("derived 3 − 2" = shift 3 in our table convention).

**The crash:** on landed runs, the walk faults at `adjust_prio_chain+0x1ec`:
`x27 = [lock+0x10]` (the lock's rb leftmost) then `[x27+0x38]`, with
`x27 = 0x301` = `W0_OFFSET | 1` — our page's leftmost pointer, **red-tagged**.
The page's `[fake_lock+0x10]` is authored as `fake_w0` (a pointer into the same
page) but reads as `fake_w0|1` at walk time.

**Why it happens:** the page's leftmost is a self-referential pointer. Some rb
operation follows it and red-tags the slot before the walk's verification reads
it. Proven value-dependent: canary page values survive intact; the real
self-referential values get tagged. Three topologies tested (empty tree,
black-root W0, fops-table parent, target−8 parent) — **all crash identically
on landed runs** ⇒ the corruption is independent of the overlay topology.

**Not fixed yet.** The corruption is pre-walk, and the writer was not caught by
fd canaries, page canaries, or register dumps. Prime suspect: a vendor-patch
difference in this Sony kernel vs the reference devices.

## Key numbers

| constant | value |
|---|---|
| KIMAGE_TEXT_BASE | 0xffffffc008000000 (KASLR slide seen: 0x133a400000) |
| kernel_phys_load / PHYS_OFFSET | 0xa8000000 / 0x80000000 |
| selinux_enforcing / init_task / init_cred | 0x225A448 / 0x201F440 / 0x20318E8 |
| ashmem_misc_fops | 0x217CC70 |
| pselect frames | 0x90 / 0x1c0, stack_fds @sp+0x50 |
| futex frames | 0x70 / 0x60 / 0x1b0, waiter @sp+0x98 |
| **waiter − fd_buffer** | **+0x18** (⇒ overlay shift = 3) |

task_struct (BTF): prio 0x84 · pi_lock 0x924 · pi_waiters 0x938 ·
pi_top_task 0x948 · **pi_blocked_on 0x950** (target.h's 0xa18 is stale) ·
cred 0x838 · sched_task_group 0x348 · seccomp 0x900

## Dead ends (do not revisit without new evidence)

* Empty-tree / black-root W0 / fops-table-parent / target−8 overlay topologies
  — all crash identically on landed runs
* configfs/physrw verification chain — structurally broken on this kernel: the
  confused configfs_buffer fields (+0x54..0x64) sit beyond the 64-byte ashmem
  name reach; the handler has no ENOTTY path (the ENOTTY happens in the VFS
  before the handler; FMODE_CAN_WRITE isn't set because misc_open swaps f_op
  after do_dentry_open)
* Shizuku — unnecessary (adb shell = uid 2000 already) and its v13.6 manager
  no longer embeds the server dex
* Execution-tuning omissions — the binary-profile keys default to 0 when
  absent; every execution section must be present

## Sweep results (recent, landed = the race consumed the overlay)

| sweep | build | landed | result |
|---|---|---|---|
| devloop2 (shift sweep, 21 runs) | 1543c0ee | 2 | both 0x339 |
| devloop4 (fd canary ×4) | 0a553956 | 1 | 0x339 (canary r4 measured the leftmost intact) |
| devloop5 (page canary ×4) | 31569305 | 1 | 0xBBBB0042 (authored leftmost consumed ✓) |
| devloop6 (black-root ×6) | 36f4caa2 | 3 | all 0x339 |
| devloop8 (fops-parent ×6) | 6b2506e7 | 2 | both 0x339 |
| devloop9 (target−8, in flight) | 012b1209 | ≥2 | 0x339 (r1, r2) |
