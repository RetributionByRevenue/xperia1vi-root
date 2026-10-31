# Building from source

## Toolchain

Any `aarch64-linux-gnu-gcc` cross-compiler works. On Debian/Ubuntu:

```bash
sudo apt install gcc-aarch64-linux-gnu
```

## Compile

From the repo root:

```bash
aarch64-linux-gnu-gcc -static -O2 -Wall \
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/devices \
  -DTARGET_CONFIG_H=\"target.h\" \
  src/core/main.c \
  src/core/util.c \
  src/core/slide.c \
  src/core/fops.c \
  src/core/pipe_physrw.c \
  src/core/root.c \
  src/core/miniadb.c \
  src/core/umh_root.c \
  -lpthread -lm \
  -o ghostlock_native
```

The binary is statically linked so it runs on bare adb shell with no
library dependencies.

## Source layout

```
src/
├── core/
│   ├── main.c              # Exploit orchestration, retry loop, child/grandchild flow
│   ├── util.c              # Spray page construction, ghost-write setup, KASLR detection
│   ├── fops.c              # pselect overlay payload — the actual UAF trigger
│   ├── slide.c             # KASLR slide detection via perf_event / KernelSnitch
│   ├── root.c              # Post-root operations: KernelSU module load, ksud install
│   ├── pipe_physrw.c       # Pipe-based kernel physical r/w primitives
│   ├── umh_root.c          # UMH (usermode helper) root path
│   ├── miniadb.c           # Minimal adb protocol for reverse-shell comms
│   ├── target.h            # Task struct offsets, waiter layout, spray page geometry
│   ├── common.h            # Shared macros and type definitions
│   ├── offset.h            # Offset calculation helpers (text_addr / data_addr)
│   ├── runtime_struct_offsets.h  # Runtime struct offset detection
│   └── kernelsnitch/       # Futex hash collision + mm_struct leak
│       ├── kernelsnitch.h
│       ├── futex_hash.h
│       ├── utils.h
│       └── timeutils.h
├── devices/
│   ├── offsets.h           # Device selector / common offset definitions
│   ├── xperia1vi/          # Sony Xperia 1 VI (SM8650, 6.1.162)
│   ├── xperia1iv/          # Sony Xperia 1 IV
│   ├── op13/               # OnePlus 13
│   ├── op15/               # OnePlus 15 (placeholder)
│   ├── ace6t/              # OnePlus Ace 6T
│   ├── cph2521/            # OPPO (CPH2521)
│   ├── findx9pro/          # OPPO Find X9 Pro
│   ├── findx9ultra/        # OPPO Find X9 Ultra
│   ├── pad4pro/            # OnePlus Pad 4 Pro
│   ├── pudding/            # (codename pudding)
│   ├── vivot4/             # Vivo T4
│   ├── vivox200ultra/      # Vivo X200 Ultra
│   └── vivoxfold3pro/      # Vivo X Fold3 Pro
```

## Adding support for another device

1. Extract a `vmlinux` or `kallsyms` from the device's boot image.
2. Use `tools/extract_target.py` and `tools/extract_btf.py` (if available in
   the parent project) to get task_struct and symbol offsets.
3. Create `src/devices/<codename>/offsets.h` with the OFFSETS_ENTRY macro.
4. Build and test with the device profile.
