/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CELL_UTIL_H
#define CELL_UTIL_H

#include <fcntl.h>
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
#define __NR_cell_kill		477
#define __NR_pidfd_configure	478
#endif

/* <linux/pidfd.h> does not get along with <fcntl.h>. */
#ifndef PIDFD_EMPTY
#define PIDFD_EMPTY		O_NOCTTY

enum pidfd_configure_cmd {
	PIDFD_SET_STRING	= 0,
	PIDFD_SET_BINARY	= 1,
	PIDFD_SET_FD		= 2,
	PIDFD_CMD_START		= 3,
};

struct pidfd_cred {
	__u32 uid;
	__u32 gid;
	__u32 ngroups;
	__u32 __spare;
	__aligned_u64 groups;
};
#endif

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP	(1ULL << 33)
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

static inline int cell_kill(int cfd, unsigned int flags)
{
	return syscall(__NR_cell_kill, cfd, flags);
}

/* A pidfd that no task is attached to yet, for one in the cell @cfd. */
static inline int pidfd_open_empty(int cfd, unsigned int flags)
{
	return syscall(SYS_pidfd_open, cfd, PIDFD_EMPTY | flags);
}

static inline int pidfd_configure(int pidfd, unsigned int cmd, const char *key,
				  const void *value, int aux)
{
	return syscall(__NR_pidfd_configure, pidfd, cmd, key, value, aux);
}

#endif /* CELL_UTIL_H */
