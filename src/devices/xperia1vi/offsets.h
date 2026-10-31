/* Sony Xperia 1 VI (XQ-EC72) — SM8650 / Snapdragon 8 Gen 3
 * kernel 6.1.162-android14-11-g40b1a8089d75-ab14960999, Clang 17.0.2 +pgo+bolt+lto
 *
 * MEASURED (not copied) via:
 *   - tools/extract_target.py --kallsyms analysis/kallsyms.txt  (symbol offsets)
 *   - tools/extract_btf.py analysis/kernel                       (struct field offsets)
 *   - capstone disassembly of analysis/vmlinux                  (call chain + frames)
 *
 * Call chain (PSELECT route): __arm64_sys_futex --bl--> do_futex --bl--> futex_wait_requeue_pi
 *   do_futex frame = 0x60, futex_wait_requeue_pi frame = 0x1b0
 *   do_futex is NOT PGO-inlined on this build (1 direct BL from __arm64_sys_futex).
 *
 * Compact waiter (10 words). waiter_word and PSELECT_SHIFT require on-device confirmation
 * (see validation checklist). C ashmem (ashmem_miscs static miscdevice), UMH root available.
 *
 * kernel_phys_load: SM8650 documented default 0xa8000000 (matches vivo T4 / X Fold3 Pro).
 *   Must be confirmed on-device: su -c 'grep -i "Kernel code" /proc/iomem'
 *   Override at runtime: KPHYS=0xa8000000 /data/local/tmp/a/e
 */

OFFSETS_ENTRY("6.1.162-android14-11-g40b1a8089d75-ab14960999",
  .kernel_phys_load=0xa8000000, STRUCT_OFFSETS_6_1,
  .kimage_text_base=0xffffffc008000000ULL,
  .off_init_task=0x0201F440, .off_init_cred=0x020318E8, .off_init_uts_ns=0x021A2DB0,
  .off_empty_zero_page=0x02201000, .off_root_task_group=0x02208580,
  .off_selinux_enforcing=0x0225A448, .off_kptr_restrict=0x0201CE78,
  .off_selinux_blob_sizes=0x015D0A28, .off_security_hook_heads=0x015D0318,
  .off_kmalloc_caches=0x015CFE58, .off_anon_pipe_buf_ops=0x0110A110,
  .off_ashmem_misc_fops=0x0217CC70, .off_ashmem_fops=0x01281910,
  .off_ashmem_ioctl=0x00C3CDF0, .off_ashmem_compat_ioctl=0x00C3D728,
  .off_ashmem_mmap=0x00C3D780, .off_ashmem_open=0x00C3D9A0,
  .off_ashmem_release=0x00C3DA28, .off_ashmem_show_fdinfo=0x00C3DB48,
  .off_configfs_read_iter=0x00464F44, .off_configfs_bin_write_iter=0x00465150,
  .off_copy_splice_read=0, .off_noop_llseek=0x00398E88,
  .off_cap_capable_active=0,
  .off_slide_nfulnl_logger=0x020127D0, .off_slide_loggers_0_1=0x02012728,
  .off_slide_boot_id=0x0227B4D8,
  .off_system_unbound_wq=0x0200AC60, .off_call_usermodehelper_exec_work=0x000D37F4,
),
