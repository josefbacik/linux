/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Cells: build them, run things in them, kill them, and try everything that is
 * not supposed to work. This is what the tests share: how to build a cell, how
 * to spawn into one, and the fixture.
 *
 * They need root, cgroup2 and tmpfs. cell_child must sit next to the binaries.
 */
#ifndef CELL_TEST_H
#define CELL_TEST_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mount.h>
#include <grp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/mount.h>
#include <linux/seccomp.h>

#include "../kselftest_harness.h"
#include "cell_util.h"

#ifndef OPEN_TREE_NAMESPACE
#define OPEN_TREE_NAMESPACE	(1 << 1)
#endif
#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP	0x00100000
#endif

static inline int sys_fsopen(const char *fs, unsigned int flags)
{
	return syscall(SYS_fsopen, fs, flags);
}

static inline int sys_fsconfig(int fd, unsigned int cmd, const char *key, const void *val, int aux)
{
	return syscall(SYS_fsconfig, fd, cmd, key, val, aux);
}

static inline int sys_fsmount(int fd, unsigned int flags, unsigned int attr)
{
	return syscall(SYS_fsmount, fd, flags, attr);
}

static inline int sys_move_mount(int from, const char *fp, int to, const char *tp,
				 unsigned int flags)
{
	return syscall(SYS_move_mount, from, fp, to, tp, flags);
}

static inline int sys_open_tree(int dfd, const char *path, unsigned int flags)
{
	return syscall(SYS_open_tree, dfd, path, flags);
}

static inline int sys_mount_setattr(int dfd, const char *path, unsigned int flags,
			     struct mount_attr *attr, size_t size)
{
	return syscall(SYS_mount_setattr, dfd, path, flags, attr, size);
}

static inline int sys_pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(SYS_pidfd_open, pid, flags);
}

#define CGROOT	"/tmp/cell_test.cgroup"

static int child_fd = -1;
static int cg_seq;

/* What goes into a cell. */
struct build {
	unsigned int	ids;		/* 0: leave alone */
	bool		no_idmap;	/* leave the tree as it is */
	bool		shared;		/* make the tree a peer of something */
	bool		no_seal;
	int		data;		/* a detached mount to put at /data, or 0 */
	int		net;		/* a network namespace to share, or 0 */
	const char	*net_str;	/* or "new" or "own" */
	bool		keep_root;	/* leave a file descriptor on the mount namespace */
	bool		cgroupfs;	/* all of cgroupfs at /data, not just the budget */
	const char	*bind;		/* or this, as it is */
};

struct cellctx {
	int	cfd;
	int	tree;		/* the detached tmpfs that becomes "/" */
	int	raw;		/* the same filesystem as the host sees it */
	int	cgfd;
	int	rootfd;		/* see keep_root */
	char	cg[128];
};

static inline int copy_child(int dirfd)
{
	static char buf[65536];
	off_t off = 0;
	ssize_t n;
	int out;

	out = openat(dirfd, "cell_child", O_CREAT | O_WRONLY, 0755);
	if (out < 0)
		return -1;
	while ((n = pread(child_fd, buf, sizeof(buf), off)) > 0) {
		if (write(out, buf, n) != n)
			return -1;
		off += n;
	}
	close(out);
	return n;
}

static inline int new_tmpfs(void)
{
	int fs, mnt;

	fs = sys_fsopen("tmpfs", FSOPEN_CLOEXEC);
	if (fs < 0)
		return -1;
	if (sys_fsconfig(fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0))
		return -1;
	mnt = sys_fsmount(fs, FSMOUNT_CLOEXEC, 0);
	close(fs);
	return mnt;
}

/* Returns 0, or the step that failed with errno set. */
static inline int cell_build(struct cellctx *c, const struct build *b)
{
	struct mount_attr attr = { .attr_set = MOUNT_ATTR_IDMAP };
	int pidns, fs, proc, nsfd;

	memset(c, 0, sizeof(*c));
	c->cfd = c->tree = c->raw = c->cgfd = c->rootfd = -1;

	snprintf(c->cg, sizeof(c->cg), CGROOT "/cell.%d.%d", getpid(), cg_seq++);
	if (mkdir(c->cg, 0755))
		return 1;
	c->cgfd = open(c->cg, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (c->cgfd < 0)
		return 2;

	c->cfd = cell_create(CELL_SELF, 0);
	if (c->cfd < 0)
		return 3;
	if (b->ids && cell_configure(c->cfd, CELL_SET_BINARY, "ids", &b->ids, sizeof(b->ids)))
		return 4;

	/* The tree, from scratch, one mount at a time. */
	c->tree = new_tmpfs();
	if (c->tree < 0)
		return 5;
	if (copy_child(c->tree) || mkdirat(c->tree, "proc", 0755) ||
	    mkdirat(c->tree, "data", 0755) ||
	    mkdirat(c->tree, "tmp", 01777) || fchmodat(c->tree, "tmp", 01777, 0))
		return 6;
	c->raw = sys_open_tree(c->tree, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	if (c->raw < 0)
		return 6;
	pidns = openat(c->tree, "su", O_CREAT | O_WRONLY, 0755);
	if (pidns < 0 || fchmod(pidns, 06755))
		return 6;
	close(pidns);
	if (!b->no_idmap && b->ids > 1) {
		attr.userns_fd = c->cfd;
		if (sys_mount_setattr(c->tree, "", AT_EMPTY_PATH, &attr, sizeof(attr)))
			return 7;
	}

	pidns = cell_open(c->cfd, CELL_OPEN_SLOT, "pids", NULL, 0);
	if (pidns < 0)
		return 8;
	fs = sys_fsopen("proc", FSOPEN_CLOEXEC);
	if (fs < 0 || sys_fsconfig(fs, FSCONFIG_SET_FD, "pidns", NULL, pidns) ||
	    sys_fsconfig(fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0))
		return 9;
	proc = sys_fsmount(fs, FSMOUNT_CLOEXEC, 0);
	if (proc < 0)
		return 10;
	if (sys_move_mount(proc, "", c->tree, "proc", MOVE_MOUNT_F_EMPTY_PATH))
		return 11;
	close(pidns);
	close(fs);
	close(proc);

	if (b->data) {
		if (b->ids > 1 &&
		    sys_mount_setattr(b->data, "", AT_EMPTY_PATH, &attr, sizeof(attr)))
			return 19;
		if (sys_move_mount(b->data, "", c->tree, "data", MOVE_MOUNT_F_EMPTY_PATH))
			return 20;
	}

	if (b->cgroupfs || b->bind) {
		int dir = open(b->bind ?: CGROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		int mnt = sys_open_tree(dir, "", AT_EMPTY_PATH | OPEN_TREE_CLONE |
					OPEN_TREE_CLOEXEC);

		if (mnt < 0 ||
		    sys_move_mount(mnt, "", c->tree, "data", MOVE_MOUNT_F_EMPTY_PATH))
			return 21;
		close(mnt);
		close(dir);
	}

	if (b->shared) {
		struct mount_attr sh = { .propagation = MS_SHARED };

		if (sys_mount_setattr(c->tree, "", AT_EMPTY_PATH | AT_RECURSIVE, &sh, sizeof(sh)))
			return 12;
	}

	nsfd = sys_open_tree(c->tree, "", AT_EMPTY_PATH | AT_RECURSIVE |
			     OPEN_TREE_NAMESPACE | OPEN_TREE_CLOEXEC);
	if (nsfd < 0)
		return 13;

	if (cell_configure(c->cfd, CELL_SET_FD, "root", NULL, nsfd))
		return 14;
	if (b->keep_root)
		c->rootfd = nsfd;
	else
		close(nsfd);
	if (cell_configure(c->cfd, CELL_SET_FD, "budget", NULL, c->cgfd))
		return 15;
	if (cell_configure(c->cfd, CELL_SET_STRING, "hostname", "celltest", 0))
		return 16;
	if (b->net && cell_configure(c->cfd, CELL_SET_FD, "net", NULL, b->net))
		return 17;
	if (b->net_str && cell_configure(c->cfd, CELL_SET_STRING, "net", b->net_str, 0))
		return 17;
	if (!b->no_seal && cell_configure(c->cfd, CELL_CMD_SEAL, NULL, NULL, 0))
		return 18;
	return 0;
}

static inline void cell_cleanup(struct cellctx *c)
{
	int i;

	if (c->cfd >= 0) {
		cell_kill(c->cfd, 0);
		close(c->cfd);
	}
	if (c->tree >= 0)
		close(c->tree);
	if (c->raw >= 0)
		close(c->raw);
	if (c->cgfd >= 0)
		close(c->cgfd);
	if (c->rootfd > 0)
		close(c->rootfd);
	for (i = 0; i < 100 && rmdir(c->cg) && errno == EBUSY; i++)
		usleep(20000);
}

/* <linux/pidfd.h> does not get along with <fcntl.h>. */
struct pidfd_info_v0 {
	__u64 mask, cgroupid;
	__u32 pid, tgid, ppid, ruid, rgid, euid, egid, suid, sgid, fsuid, fsgid;
	__s32 exit_code;
};
#define PIDFD_GET_INFO_V0	_IOWR(0xFF, 11, struct pidfd_info_v0)
#define PIDFD_INFO_EXIT_V0	(1 << 3)

/* The pid of what a pidfd is on, as the caller sees it, or -1. */
static inline pid_t pidfd_nr(int pidfd)
{
	struct pidfd_info_v0 info = {};

	if (ioctl(pidfd, PIDFD_GET_INFO_V0, &info))
		return -1;
	return info.pid;
}

/* argv as a block of NUL terminated strings: "cell_child\0<a>\0<b>\0<c>\0" */
static inline int set_argv(int pidfd, const char *a, const char *b, const char *c)
{
	char blk[256];
	int len = 0;

	len += sprintf(blk + len, "cell_child") + 1;
	if (a)
		len += sprintf(blk + len, "%s", a) + 1;
	if (b)
		len += sprintf(blk + len, "%s", b) + 1;
	if (c)
		len += sprintf(blk + len, "%s", c) + 1;
	return pidfd_configure(pidfd, PIDFD_SET_BINARY, "argv", blk, len);
}

/* There is no task, and so no pid, before it is started. */
static inline int prepare(int cfd, const char *a, const char *b, const char *c)
{
	int pidfd = pidfd_open_empty(cfd, 0);
	int null;

	if (pidfd < 0)
		return -1;
	null = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (pidfd_configure(pidfd, PIDFD_SET_STRING, "exec", "/cell_child", 0) ||
	    set_argv(pidfd, a, b, c) ||
	    pidfd_configure(pidfd, PIDFD_SET_BINARY, "envp", "CELL=yes", 9) ||
	    pidfd_configure(pidfd, PIDFD_SET_FD, "0", NULL, null) ||
	    pidfd_configure(pidfd, PIDFD_SET_FD, "1", NULL, STDERR_FILENO) ||
	    pidfd_configure(pidfd, PIDFD_SET_FD, "2", NULL, STDERR_FILENO)) {
		close(pidfd);
		return -1;
	}
	close(null);
	return pidfd;
}

static inline int spawn(int cfd, pid_t *pid, const char *a, const char *b, const char *c)
{
	int pidfd = prepare(cfd, a, b, c);

	if (pidfd >= 0 && pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0)) {
		close(pidfd);
		return -1;
	}
	if (pidfd >= 0 && pid)
		*pid = pidfd_nr(pidfd);
	return pidfd;
}

static inline int cell_wait(int cfd)
{
	int status = -1;

	if (read(cfd, &status, sizeof(status)) != sizeof(status))
		return -1;
	return status;
}

/* The same, once the cell is dead, or -2 if that takes too long. */
static inline int cell_wait_dead(int cfd)
{
	struct pollfd pfd = { .fd = cfd, .events = POLLIN };

	if (poll(&pfd, 1, 10000) != 1)
		return -2;
	return cell_wait(cfd);
}

static inline unsigned int cell_state(int cfd)
{
	struct cell_info info = { .mask = CELL_INFO_STATE };

	if (cell_info(cfd, &info, sizeof(info), 0) || !(info.mask & CELL_INFO_STATE))
		return ~0U;
	return info.state;
}

/* Not by cgroup.procs, which does not list a task that is on its way out. */
static inline int cg_populated(const char *cg)
{
	char path[192], buf[256] = {};
	int fd;

	snprintf(path, sizeof(path), "%s/cgroup.events", cg);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	if (read(fd, buf, sizeof(buf) - 1) < 0)
		buf[0] = 0;
	close(fd);
	if (strstr(buf, "populated 0"))
		return 0;
	return strstr(buf, "populated 1") ? 1 : -1;
}

/* The kuid the host sees @pid run as. */
static inline long host_uid(pid_t pid)
{
	char path[64];
	struct stat st;

	snprintf(path, sizeof(path), "/proc/%d", pid);
	if (stat(path, &st))
		return -1;
	return st.st_uid;
}

static inline int write_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY), ret;

	if (fd < 0)
		return -1;
	ret = write(fd, val, strlen(val)) < 0 ? -1 : 0;
	close(fd);
	return ret;
}

FIXTURE(cell) {
	struct cellctx c;
};

FIXTURE_SETUP(cell)
{
	char path[PATH_MAX], *slash;

	if (geteuid())
		SKIP(return, "needs root");
	if (cell_create(-1, 0) == -1 && errno == ENOSYS)
		SKIP(return, "no cells in this kernel");

	/* Next to this binary. */
	snprintf(path, sizeof(path) - 16, "%s", (char *)getauxval(AT_EXECFN));
	slash = strrchr(path, '/');
	strcpy(slash ? slash + 1 : path, "cell_child");
	child_fd = open(path, O_RDONLY | O_CLOEXEC);
	ASSERT_GE(child_fd, 0);

	mkdir(CGROOT, 0755);
	if (mount("none", CGROOT, "cgroup2", 0, NULL) && errno != EBUSY)
		SKIP(return, "no cgroup2");
	self->c.cfd = self->c.tree = self->c.raw = self->c.cgfd = -1;
}

FIXTURE_TEARDOWN(cell)
{
	cell_cleanup(&self->c);
	umount2(CGROOT, MNT_DETACH);
	close(child_fd);
}

#define RUN_IN_CELL(what) do {							\
	int pidfd;								\
	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);	\
	pidfd = spawn(self->c.cfd, NULL, what, NULL, NULL);			\
	ASSERT_GE(pidfd, 0);							\
	EXPECT_EQ(cell_wait(self->c.cfd), 0);					\
	close(pidfd);								\
} while (0)

#endif /* CELL_TEST_H */
