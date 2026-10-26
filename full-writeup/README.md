# Full Writeup — GhostLock Root on the Sony Xperia 1 VI

The complete history of the project: what was tried, what was ruled out, what
was measured, and what finally worked. No hand-waving — every claim below was
verified on the device, in a QEMU VM, or by static analysis of the kernel.

## Contents

| File | What it is |
|---|---|
| `HISTORY.md` | The narrative: phases, pivots, dead ends, the breakthrough |
| `CONFIRMED-FINDINGS.md` | The hard technical facts: measured geometry, offsets, mechanisms, dead ends |
| `FINAL-RUN.md` | The winning run, stage by stage, plus the post-exploit state |
| `appendix-set1-findings.md` | Set 1 (our C exploit) findings as recorded at the time |
| `appendix-set2-findings.md` | Set 2 (ghostlock-app core) findings as recorded at the time |
| `appendix-attempt-log.md` | The full chronological attempt log (~50 device boots) |

## One-paragraph summary

Root was achieved on a locked-bootloader Xperia 1 VI (XQ-EC72, kernel
`6.1.162-android14-11-g40b1a8089d75-ab14960999`) with GhostLock
(CVE-2026-43499): a KernelSnitch futex-collision leak feeds a pselect/futex
PI-walk race that reinterprets a sprayed user page as kernel rbtree/PI-waiter
nodes; the rbtree-erase trick performs arbitrary writes — W1 zeroes
`selinux_enforcing`, W2 overwrites a child task's `cred` with `init_cred` —
then `ksud` (from the ReSukiSU manager) late-loads `kernelsu.ko` into the
running kernel. Root is per-boot: the module lives in memory only.
