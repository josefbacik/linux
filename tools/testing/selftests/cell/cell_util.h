/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CELL_UTIL_H
#define CELL_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/types.h>

#include "../../../../include/uapi/linux/cell.h"

#ifndef CELL_SELF
#define CELL_SELF		-10005
#endif

#ifndef __NR_cell_create
#define __NR_cell_create	473
#define __NR_cell_configure	474
#define __NR_cell_info		475
#define __NR_cell_open		476
#define __NR_task_configure	477
#endif

#ifndef CLONE_EMBRYO
#define CLONE_EMBRYO		(1ULL << 38)
#define CLONE_INTO_CELL		(1ULL << 39)
#endif
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP	(1ULL << 33)
#endif
#ifndef CLONE_AUTOREAP
#define CLONE_AUTOREAP		(1ULL << 34)
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD		0x00001000
#endif

#define CELL_WINDOW_FIRST	0x80000000U
#define CELL_WINDOW_LAST	0xfffeffffU

struct cell_clone_args {
	__aligned_u64 flags;
	__aligned_u64 pidfd;
	__aligned_u64 child_tid;
	__aligned_u64 parent_tid;
	__aligned_u64 exit_signal;
	__aligned_u64 stack;
	__aligned_u64 stack_size;
	__aligned_u64 tls;
	__aligned_u64 set_tid;
	__aligned_u64 set_tid_size;
	__aligned_u64 cgroup;
	__aligned_u64 cell;
};

static inline int cell_create(int parent, unsigned int flags)
{
	return syscall(__NR_cell_create, parent, flags);
}

static inline int cell_configure(int cfd, unsigned int cmd, const char *key,
				 const void *value, int aux)
{
	return syscall(__NR_cell_configure, cfd, cmd, key, value, aux);
}

static inline int cell_info(int cfd, struct cell_info *info, size_t size,
			    unsigned int flags)
{
	return syscall(__NR_cell_info, cfd, info, size, flags);
}

static inline int cell_open(int cfd, unsigned int what, const char *key,
			    const void *arg, unsigned int flags)
{
	return syscall(__NR_cell_open, cfd, what, key, arg, flags);
}

static inline int task_configure(int pidfd, unsigned int cmd, const char *key,
				 const void *value, int aux)
{
	return syscall(__NR_task_configure, pidfd, cmd, key, value, aux);
}

#endif /* CELL_UTIL_H */
