// SPDX-License-Identifier: GPL-2.0
/*
 * Cells: build them, run things in them, kill them, and try everything that is
 * not supposed to work.
 *
 * Needs root, cgroup2 and tmpfs. cell_child must sit next to this binary.
 */
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
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
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

static int sys_fsopen(const char *fs, unsigned int flags)
{
	return syscall(SYS_fsopen, fs, flags);
}

static int sys_fsconfig(int fd, unsigned int cmd, const char *key, const void *val, int aux)
{
	return syscall(SYS_fsconfig, fd, cmd, key, val, aux);
}

static int sys_fsmount(int fd, unsigned int flags, unsigned int attr)
{
	return syscall(SYS_fsmount, fd, flags, attr);
}

static int sys_move_mount(int from, const char *fp, int to, const char *tp, unsigned int flags)
{
	return syscall(SYS_move_mount, from, fp, to, tp, flags);
}

static int sys_open_tree(int dfd, const char *path, unsigned int flags)
{
	return syscall(SYS_open_tree, dfd, path, flags);
}

static int sys_mount_setattr(int dfd, const char *path, unsigned int flags,
			     struct mount_attr *attr, size_t size)
{
	return syscall(SYS_mount_setattr, dfd, path, flags, attr, size);
}

static int sys_pidfd_open(pid_t pid, unsigned int flags)
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
};

struct cellctx {
	int	cfd;
	int	tree;		/* the detached tmpfs that becomes "/" */
	int	raw;		/* the same filesystem as the host sees it */
	int	cgfd;
	char	cg[128];
};

static int copy_child(int dirfd)
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

static int new_tmpfs(void)
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
static int cell_build(struct cellctx *c, const struct build *b)
{
	struct mount_attr attr = { .attr_set = MOUNT_ATTR_IDMAP };
	int pidns, fs, proc, nsfd;

	memset(c, 0, sizeof(*c));
	c->cfd = c->tree = c->raw = c->cgfd = -1;

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
	close(nsfd);
	if (cell_configure(c->cfd, CELL_SET_FD, "budget", NULL, c->cgfd))
		return 15;
	if (cell_configure(c->cfd, CELL_SET_STRING, "hostname", "celltest", 0))
		return 16;
	if (!b->no_seal && cell_configure(c->cfd, CELL_CMD_SEAL, NULL, NULL, 0))
		return 18;
	return 0;
}

static void cell_cleanup(struct cellctx *c)
{
	int i;

	if (c->cfd >= 0) {
		cell_configure(c->cfd, CELL_CMD_KILL, NULL, NULL, 0);
		close(c->cfd);
	}
	if (c->tree >= 0)
		close(c->tree);
	if (c->raw >= 0)
		close(c->raw);
	if (c->cgfd >= 0)
		close(c->cgfd);
	for (i = 0; i < 100 && rmdir(c->cg) && errno == EBUSY; i++)
		usleep(20000);
}

static int embryo(int cfd, pid_t *pid)
{
	int pidfd = -1;
	struct cell_clone_args ca = {
		.flags = CLONE_PIDFD | CLONE_EMBRYO | CLONE_INTO_CELL | CLONE_AUTOREAP,
		.pidfd = (uintptr_t)&pidfd,
		.cell = cfd,
	};
	long ret = syscall(SYS_clone3, &ca, sizeof(ca));

	if (ret < 0)
		return -1;
	if (pid)
		*pid = ret;
	return pidfd;
}

/* argv as a block of NUL terminated strings: "cell_child\0<a>\0<b>\0<c>\0" */
static int set_argv(int pidfd, const char *a, const char *b, const char *c)
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
	return task_configure(pidfd, TASK_SET_BINARY, "argv", blk, len);
}

static int prepare(int cfd, pid_t *pid, const char *a, const char *b, const char *c)
{
	int pidfd = embryo(cfd, pid);
	int null;

	if (pidfd < 0)
		return -1;
	null = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (task_configure(pidfd, TASK_SET_STRING, "exec", "/cell_child", 0) ||
	    set_argv(pidfd, a, b, c) ||
	    task_configure(pidfd, TASK_SET_BINARY, "envp", "CELL=yes", 9) ||
	    task_configure(pidfd, TASK_SET_FD, "0", NULL, null) ||
	    task_configure(pidfd, TASK_SET_FD, "1", NULL, STDERR_FILENO) ||
	    task_configure(pidfd, TASK_SET_FD, "2", NULL, STDERR_FILENO)) {
		close(pidfd);
		return -1;
	}
	close(null);
	return pidfd;
}

static int spawn(int cfd, pid_t *pid, const char *a, const char *b, const char *c)
{
	int pidfd = prepare(cfd, pid, a, b, c);

	if (pidfd >= 0 && task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0)) {
		close(pidfd);
		return -1;
	}
	return pidfd;
}

static int cell_wait(int cfd)
{
	int status = -1;

	if (read(cfd, &status, sizeof(status)) != sizeof(status))
		return -1;
	return status;
}

static unsigned int cell_state(int cfd)
{
	struct cell_info info = { .mask = CELL_INFO_STATE };

	if (cell_info(cfd, &info, sizeof(info), 0) || !(info.mask & CELL_INFO_STATE))
		return ~0U;
	return info.state;
}

/* Not by cgroup.procs, which does not list a task that is on its way out. */
static int cg_populated(const char *cg)
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
static long host_uid(pid_t pid)
{
	char path[64];
	struct stat st;

	snprintf(path, sizeof(path), "/proc/%d", pid);
	if (stat(path, &st))
		return -1;
	return st.st_uid;
}

static int write_file(const char *path, const char *val)
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

TEST_F(cell, life)
{
	struct cell_info info = { .mask = ~0ULL };
	struct pollfd pfd;
	pid_t pid;
	int pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true }), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_BUILDING);

	/* Not before it is sealed. */
	EXPECT_EQ(embryo(self->c.cfd, NULL), -1);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_EQ(cell_configure(self->c.cfd, CELL_CMD_SEAL, NULL, NULL, 0), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_SEALED);

	/* Sealed is sealed. */
	EXPECT_EQ(cell_configure(self->c.cfd, CELL_SET_STRING, "hostname", "x", 0), -1);
	EXPECT_EQ(errno, EBUSY);
	EXPECT_EQ(cell_configure(self->c.cfd, CELL_CMD_SEAL, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EBUSY);
	EXPECT_EQ(cell_open(self->c.cfd, CELL_OPEN_SLOT, "net", NULL, 0), -1);
	EXPECT_EQ(errno, EBUSY);

	pidfd = spawn(self->c.cfd, &pid, "exit", "7", NULL);
	ASSERT_GE(pidfd, 0);

	pfd = (struct pollfd){ .fd = self->c.cfd, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 10000), 1);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	EXPECT_EQ(cell_wait(self->c.cfd), 7 << 8);
	/* Repeatable. */
	EXPECT_EQ(cell_wait(self->c.cfd), 7 << 8);

	ASSERT_EQ(cell_info(self->c.cfd, &info, sizeof(info), 0), 0);
	EXPECT_NE(info.id, 0);
	EXPECT_EQ(info.parent_id, 0);
	EXPECT_EQ(info.ids_count, 65536);
	EXPECT_EQ(info.exit_status, 7 << 8);
	EXPECT_NE(info.budget_cgroupid, 0);
	EXPECT_EQ(info.mask, info.supported_mask);

	/* Nothing goes into a dead cell. */
	EXPECT_EQ(embryo(self->c.cfd, NULL), -1);
	EXPECT_EQ(errno, ESRCH);
	EXPECT_EQ(cg_populated(self->c.cg), 0);
	close(pidfd);
}

TEST_F(cell, nothing_inherited)
{
	/* Things a fork would have passed on. */
	int junk = open("/etc/passwd", O_RDONLY);

	ASSERT_GE(junk, 0);
	ASSERT_EQ(chdir("/etc"), 0);
	setenv("SECRET", "hunter2", 1);
	RUN_IN_CELL("basic");
	close(junk);
}

TEST_F(cell, membership)
{
	RUN_IN_CELL("membership");
}

TEST_F(cell, files_impart_no_privilege)
{
	struct stat st;

	RUN_IN_CELL("setid");

	/* And this is what the host finds. */
	ASSERT_EQ(fstatat(self->c.raw, "tmp/a", &st, 0), 0);
	EXPECT_EQ(st.st_mode & (S_ISUID | S_ISGID), 0);
	/* On disk the ids of the cell count from 0. No kuid of its block got there. */
	EXPECT_EQ(st.st_uid, 33);
	ASSERT_EQ(fstatat(self->c.raw, "su", &st, 0), 0);
	EXPECT_EQ(st.st_mode & 07777, 0755);
	EXPECT_EQ(st.st_uid, 0);
}

TEST_F(cell, bad_arguments)
{
	unsigned int ids;
	char path[64];
	int cfd;

	EXPECT_EQ(cell_create(CELL_SELF, 1), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(cell_create(0, 0), -1);
	EXPECT_EQ(errno, EINVAL);

	cfd = cell_create(CELL_SELF, 0);
	ASSERT_GE(cfd, 0);
	EXPECT_EQ(fcntl(cfd, F_GETFD) & FD_CLOEXEC, FD_CLOEXEC);

	/* A handle is passed on, not opened again. */
	snprintf(path, sizeof(path), "/proc/self/fd/%d", cfd);
	EXPECT_EQ(open(path, O_RDONLY), -1);
	EXPECT_EQ(errno, ENXIO);
	EXPECT_EQ(open(path, O_RDWR), -1);
	EXPECT_EQ(errno, EPERM);

	EXPECT_EQ(cell_configure(cfd, 99, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_STRING, "nonsense", "x", 0), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_FD, "root", NULL, cfd), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(cell_configure(0, CELL_CMD_SEAL, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	ids = 1000;
	EXPECT_EQ(cell_configure(cfd, CELL_SET_BINARY, "ids", &ids, sizeof(ids)), -1);
	EXPECT_EQ(errno, EINVAL);
	ids = 65536;
	EXPECT_EQ(cell_configure(cfd, CELL_SET_BINARY, "ids", &ids, sizeof(ids)), 0);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_BINARY, "ids", &ids, sizeof(ids)), -1);
	EXPECT_EQ(errno, EBUSY);
	/* No root, no budget. */
	EXPECT_EQ(cell_configure(cfd, CELL_CMD_SEAL, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	close(cfd);
}

TEST_F(cell, kill_while_building)
{
	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true }), 0);
	ASSERT_EQ(cell_configure(self->c.cfd, CELL_CMD_KILL, NULL, NULL, 0), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	EXPECT_EQ(cell_wait(self->c.cfd), SIGKILL);
	EXPECT_EQ(cell_configure(self->c.cfd, CELL_CMD_SEAL, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EBUSY);
	/* Idempotent. */
	EXPECT_EQ(cell_configure(self->c.cfd, CELL_CMD_KILL, NULL, NULL, 0), 0);
}

TEST_F(cell, kill_fork_bomb)
{
	int pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	ASSERT_EQ(write_file(({ static char p[192];
				snprintf(p, sizeof(p), "%s/pids.max", self->c.cg); p; }),
			     "200") == 0 || errno == ENOENT, 1);
	pidfd = spawn(self->c.cfd, NULL, "forkbomb", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	usleep(300000);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_RUNNING);

	ASSERT_EQ(cell_configure(self->c.cfd, CELL_CMD_KILL, NULL, NULL, 0), 0);
	EXPECT_EQ(cell_wait(self->c.cfd), SIGKILL);
	/* DEAD means gone. */
	EXPECT_EQ(cg_populated(self->c.cg), 0);
	close(pidfd);
}

/* A cell lives for as long as somebody holds a handle on it, and no longer. */
TEST_F(cell, dies_with_its_last_handle)
{
	struct pollfd pfd;
	int pidfd, second;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = spawn(self->c.cfd, NULL, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	pfd = (struct pollfd){ .fd = pidfd, .events = POLLIN };

	/* Any handle will do, so a cell can be handed on. */
	second = dup(self->c.cfd);
	ASSERT_GE(second, 0);
	close(self->c.cfd);
	self->c.cfd = -1;
	EXPECT_EQ(poll(&pfd, 1, 300), 0);

	close(second);
	EXPECT_EQ(poll(&pfd, 1, 10000), 1);
	close(pidfd);
}

/* Whoever made a cell is killed, and had told nobody about it. */
TEST_F(cell, dies_with_its_maker)
{
	char cg[sizeof(self->c.cg)] = {};
	int p[2], i, populated = -1;
	pid_t pid;

	ASSERT_EQ(pipe(p), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		struct build b = { .ids = 65536 };
		struct cellctx c;

		if (cell_build(&c, &b) ||
		    spawn(c.cfd, NULL, "pause", NULL, NULL) < 0 ||
		    write(p[1], c.cg, sizeof(c.cg)) != sizeof(c.cg))
			_exit(1);
		for (;;)
			pause();
	}
	close(p[1]);
	ASSERT_EQ(read(p[0], cg, sizeof(cg)), sizeof(cg));
	close(p[0]);
	EXPECT_EQ(cg_populated(cg), 1);

	ASSERT_EQ(kill(pid, SIGKILL), 0);
	ASSERT_EQ(waitpid(pid, NULL, 0), pid);
	for (i = 0; i < 200 && populated; i++) {
		usleep(50000);
		populated = cg_populated(cg);
	}
	EXPECT_EQ(populated, 0);
	for (i = 0; i < 100 && rmdir(cg) && errno == EBUSY; i++)
		usleep(20000);
}

TEST_F(cell, embryo)
{
	struct pollfd pfd;
	int pidfd, other;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);

	pidfd = prepare(self->c.cfd, &pid, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);

	/* It exists, in the cell, as the cell's root, and holds nothing. */
	EXPECT_GE(host_uid(pid), (long)CELL_WINDOW_FIRST);
	EXPECT_EQ(cg_populated(self->c.cg), 1);

	/* It says nothing of where it came from, and nobody gets to look. */
	do {
		char path[64], buf[64] = {};
		int fd;

		snprintf(path, sizeof(path), "/proc/%d/comm", pid);
		fd = open(path, O_RDONLY);
		ASSERT_GE(fd, 0);
		ASSERT_GT(read(fd, buf, sizeof(buf) - 1), 0);
		EXPECT_STREQ(buf, "embryo\n");
		close(fd);
		snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			EXPECT_EQ(read(fd, buf, sizeof(buf)), -1);
			EXPECT_EQ(errno, EPERM);
			close(fd);
		}
		EXPECT_EQ(ptrace(PTRACE_SEIZE, pid, 0, 0), -1);
		EXPECT_EQ(errno, EPERM);
	} while (0);

	/* Only the file clone3() returned will do. */
	other = sys_pidfd_open(pid, 0);
	ASSERT_GE(other, 0);
	EXPECT_EQ(task_configure(other, TASK_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EPERM);
	close(other);

	/* What may not be given. */
	EXPECT_EQ(task_configure(pidfd, TASK_SET_FD, "3", NULL, self->c.cfd), -1);
	EXPECT_EQ(errno, EPERM);
	other = open("/proc/self/ns/net", O_RDONLY);
	EXPECT_EQ(task_configure(pidfd, TASK_SET_FD, "3", NULL, other), -1);
	EXPECT_EQ(errno, EPERM);
	close(other);
	EXPECT_EQ(task_configure(pidfd, TASK_SET_FD, "3", NULL, pidfd), -1);
	EXPECT_EQ(errno, EPERM);
	EXPECT_EQ(task_configure(pidfd, TASK_SET_FD, "nonsense", NULL, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(task_configure(pidfd, TASK_SET_BINARY, "argv", "unterminated", 12), -1);
	EXPECT_EQ(errno, EINVAL);
	/* An id the cell does not have. */
	EXPECT_EQ(task_configure(pidfd, TASK_SET_BINARY, "cred",
				 &(struct task_cred){ .uid = 70000 }, sizeof(struct task_cred)), -1);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_EQ(task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0), 0);
	EXPECT_EQ(task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EBUSY);
	EXPECT_EQ(task_configure(pidfd, TASK_SET_STRING, "exec", "/x", 0), -1);
	EXPECT_EQ(errno, EBUSY);
	close(pidfd);

	/* A second one, into the running cell. */
	pidfd = spawn(self->c.cfd, NULL, "second", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	pfd = (struct pollfd){ .fd = pidfd, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 10000), 1);
	do {
		/* <linux/pidfd.h> does not get along with <fcntl.h>. */
		struct {
			__u64 mask, cgroupid;
			__u32 pid, tgid, ppid, ruid, rgid, euid, egid, suid, sgid, fsuid, fsgid;
			__s32 exit_code;
		} info = { .mask = 1 << 3 /* PIDFD_INFO_EXIT */ };

		ASSERT_EQ(ioctl(pidfd, _IOWR(0xFF, 11, info), &info), 0);
		EXPECT_EQ(info.exit_code, 0);
	} while (0);
	close(pidfd);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_RUNNING);

	/* One that nobody can start any more goes away. */
	pidfd = prepare(self->c.cfd, &pid, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	other = sys_pidfd_open(pid, 0);
	ASSERT_GE(other, 0);
	close(pidfd);
	pfd = (struct pollfd){ .fd = other, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 10000), 1);
	close(other);
}

TEST_F(cell, exec_failure_is_reported)
{
	int pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = prepare(self->c.cfd, NULL, "basic", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(task_configure(pidfd, TASK_SET_STRING, "exec", "/no/such/file", 0), 0);
	EXPECT_EQ(task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, ENOENT);
	/* That was the cell's init. */
	EXPECT_EQ(cell_wait(self->c.cfd), SIGKILL);
	close(pidfd);
}

TEST_F(cell, cred)
{
	int pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = prepare(self->c.cfd, NULL, "uid", "33", "44");
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(task_configure(pidfd, TASK_SET_BINARY, "cred",
				 &(struct task_cred){ .uid = 33, .gid = 44 },
				 sizeof(struct task_cred)), 0);
	ASSERT_EQ(task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0), 0);
	EXPECT_EQ(cell_wait(self->c.cfd), 0);
	close(pidfd);
}

TEST_F(cell, nobody_enters)
{
	static const char * const ns[] = { "user", "mnt", "pid", "net", "ipc", "uts", "cgroup" };
	char path[64];
	unsigned int i;
	pid_t pid;
	int pidfd, fd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = spawn(self->c.cfd, &pid, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);

	for (i = 0; i < ARRAY_SIZE(ns); i++) {
		snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, ns[i]);
		fd = open(path, O_RDONLY);
		ASSERT_GE(fd, 0);
		EXPECT_EQ(setns(fd, 0), -1) TH_LOG("entered %s", ns[i]);
		EXPECT_EQ(errno, EPERM) TH_LOG("%s", ns[i]);
		close(fd);
	}
	EXPECT_EQ(setns(pidfd, CLONE_NEWNET), -1);
	EXPECT_EQ(errno, EPERM);
	close(pidfd);
}

TEST_F(cell, stays_in_its_budget)
{
	char buf[32];
	pid_t pid;
	int pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = spawn(self->c.cfd, &pid, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);

	snprintf(buf, sizeof(buf), "%d", pid);
	EXPECT_EQ(write_file(CGROOT "/cgroup.procs", buf), -1);
	EXPECT_EQ(errno, EPERM);
	close(pidfd);
}

TEST_F(cell, budget_is_handed_over)
{
	struct stat st;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	ASSERT_EQ(fstat(self->c.cgfd, &st), 0);
	EXPECT_GE(st.st_uid, CELL_WINDOW_FIRST);
	ASSERT_EQ(fstatat(self->c.cgfd, "cgroup.procs", &st, 0), 0);
	EXPECT_GE(st.st_uid, CELL_WINDOW_FIRST);
	/* Limits stay with whoever is above. */
	ASSERT_EQ(fstatat(self->c.cgfd, "cgroup.max.depth", &st, 0), 0);
	EXPECT_EQ(st.st_uid, 0);
}

TEST_F(cell, tree_must_be_for_the_cell)
{
	/* A writable tmpfs of the host's, not idmapped. */
	EXPECT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_idmap = true }), 18);
	EXPECT_EQ(errno, EOVERFLOW);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_BUILDING);
}

TEST_F(cell, nothing_propagates_in)
{
	char path[64], line[512];
	pid_t pid;
	int pidfd;
	FILE *f;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .shared = true }), 0);
	pidfd = spawn(self->c.cfd, &pid, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);

	snprintf(path, sizeof(path), "/proc/%d/mountinfo", pid);
	f = fopen(path, "r");
	ASSERT_NE(f, NULL);
	while (fgets(line, sizeof(line), f)) {
		EXPECT_EQ(strstr(line, "shared:"), NULL) TH_LOG("%s", line);
		EXPECT_EQ(strstr(line, "master:"), NULL) TH_LOG("%s", line);
	}
	fclose(f);
	close(pidfd);
}

TEST_F(cell, sockets_carry_bytes)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	char ctl[CMSG_SPACE(sizeof(int))] = {}, c = 'h';
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = ctl, .msg_controllen = sizeof(ctl),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	int pidfd, sv[2], lsock, conn, zero = 0, cwd;
	struct ucred uc;
	socklen_t len;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true }), 0);

	/* A listener of the host's that the cell can reach by name. */
	lsock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	cwd = open(".", O_RDONLY | O_DIRECTORY);
	ASSERT_EQ(fchdir(self->c.raw), 0);
	strcpy(addr.sun_path, "tmp/sock");
	ASSERT_EQ(bind(lsock, (struct sockaddr *)&addr, sizeof(addr)), 0);
	ASSERT_EQ(chmod("tmp/sock", 0777), 0);
	ASSERT_EQ(fchdir(cwd), 0);
	ASSERT_EQ(listen(lsock, 1), 0);
	ASSERT_EQ(cell_configure(self->c.cfd, CELL_CMD_SEAL, NULL, NULL, 0), 0);

	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv), 0);
	pidfd = prepare(self->c.cfd, NULL, "unix", NULL, NULL);
	ASSERT_GE(pidfd, 0);

	/* A file in flight from before the socket is given away. */
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &zero, sizeof(int));
	c = 'q';
	ASSERT_EQ(sendmsg(sv[0], &msg, 0), 1);
	c = 'h';

	ASSERT_EQ(task_configure(pidfd, TASK_SET_FD, "3", NULL, sv[1]), 0);
	close(sv[1]);
	ASSERT_EQ(task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0), 0);

	/* From the moment it was given away. */
	EXPECT_EQ(sendmsg(sv[0], &msg, 0), -1);
	EXPECT_EQ(errno, EPERM);

	ASSERT_EQ(read(sv[0], &c, 1), 1);
	EXPECT_EQ(c, 'a');
	ASSERT_EQ(read(sv[0], &c, 1), 1);
	EXPECT_EQ(c, 'b');
	ASSERT_EQ(write(sv[0], "h", 1), 1);

	conn = accept(lsock, NULL, NULL);
	ASSERT_GE(conn, 0);
	len = sizeof(uc);
	EXPECT_EQ(getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &uc, &len), -1);
	EXPECT_EQ(errno, ENODATA);
	c = 'h';
	EXPECT_EQ(sendmsg(conn, &msg, 0), -1);
	EXPECT_EQ(errno, EPERM);
	ASSERT_EQ(read(conn, &c, 1), 1);
	EXPECT_EQ(c, 'c');

	EXPECT_EQ(cell_wait(self->c.cfd), 0);
	close(conn);
	close(lsock);
	close(sv[0]);
	close(pidfd);
	close(cwd);
}

TEST_F(cell, ids_never_reach_a_disk)
{
	int pidfd, host, fd;

	/* A filesystem of the host's, wide open, and a way to it past the tree. */
	fd = new_tmpfs();
	ASSERT_GE(fd, 0);
	host = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(host, 0);
	close(fd);
	ASSERT_EQ(fchmod(host, 0777), 0);
	fd = openat(host, "world", O_CREAT | O_WRONLY, 0666);
	ASSERT_GE(fd, 0);
	close(fd);

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = prepare(self->c.cfd, NULL, "dirfd", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(task_configure(pidfd, TASK_SET_FD, "3", NULL, host), 0);
	ASSERT_EQ(task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0), 0);
	EXPECT_EQ(cell_wait(self->c.cfd), 0);

	/* Nor by the hand of the host. */
	EXPECT_EQ(fchownat(host, "world", CELL_WINDOW_FIRST + 5, -1, 0), -1);
	EXPECT_EQ(errno, EOVERFLOW);
	EXPECT_EQ(fchownat(host, "world", -1, CELL_WINDOW_LAST, 0), -1);
	EXPECT_EQ(errno, EOVERFLOW);
	EXPECT_EQ(fchownat(host, "world", CELL_WINDOW_FIRST - 1, CELL_WINDOW_FIRST - 1, 0), 0);
	close(host);
	close(pidfd);
}

TEST_F(cell, window_is_the_kernels)
{
	char path[64];
	int sync[2];
	pid_t pid;
	char c;

	ASSERT_EQ(pipe(sync), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		if (unshare(CLONE_NEWUSER))
			_exit(1);
		if (write(sync[1], "x", 1) != 1)
			_exit(1);
		pause();
		_exit(0);
	}
	ASSERT_EQ(read(sync[0], &c, 1), 1);

	snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
	EXPECT_EQ(write_file(path, "0 2147483648 1"), -1);
	EXPECT_EQ(errno, EPERM);
	EXPECT_EQ(write_file(path, "0 2147483000 1000"), -1);
	EXPECT_EQ(errno, EPERM);
	EXPECT_EQ(write_file(path, "0 4294900000 10"), -1);
	EXPECT_EQ(errno, EPERM);
	EXPECT_EQ(write_file(path, "0 2147483000 648"), 0);
	snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
	EXPECT_EQ(write_file(path, "0 3000000000 1"), -1);
	EXPECT_EQ(errno, EPERM);

	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

TEST_F(cell, blocks_do_not_overlap)
{
	struct cellctx other;
	long a, b;
	pid_t pid;
	int p1, p2;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	ASSERT_EQ(cell_build(&other, &(struct build){ .ids = 65536 }), 0);
	p1 = spawn(self->c.cfd, &pid, "pause", NULL, NULL);
	ASSERT_GE(p1, 0);
	a = host_uid(pid);
	p2 = spawn(other.cfd, &pid, "pause", NULL, NULL);
	ASSERT_GE(p2, 0);
	b = host_uid(pid);

	EXPECT_GE(a, (long)CELL_WINDOW_FIRST);
	EXPECT_LE(a, (long)CELL_WINDOW_LAST);
	EXPECT_EQ(a % 65536, 0);
	EXPECT_EQ(b % 65536, 0);
	EXPECT_NE(a, b);

	close(p1);
	close(p2);
	cell_cleanup(&other);
}

static int drop_caps(void)
{
	struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3 };
	struct __user_cap_data_struct data[2] = {};

	return syscall(SYS_capset, &hdr, data);
}

/* A one-id cell runs on the kuid of whoever made it. That must not count. */
/* Have the kernel send @pid a SIGUSR1 on behalf of the caller. */
static int sigio_to(pid_t pid)
{
	int sp[2], ret = -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		return -1;
	if (!fcntl(sp[0], F_SETOWN, pid) && !fcntl(sp[0], F_SETSIG, SIGUSR1) &&
	    !fcntl(sp[0], F_SETFL, O_ASYNC) && write(sp[1], "x", 1) == 1)
		ret = 0;
	close(sp[0]);
	close(sp[1]);
	return ret;
}

#define V1ROOT	"/tmp/cell-test-v1"

TEST_F(cell, equal_uid_means_nothing)
{
	int pidfd, status;
	pid_t pid, plain, prober;
	bool v1;

	/* A cgroup v1 hierarchy with a group that uid 1000 may write to. */
	mkdir(V1ROOT, 0755);
	v1 = !mount("none", V1ROOT, "cgroup", 0, "none,name=celltest");
	if (v1) {
		ASSERT_EQ(mkdir(V1ROOT "/sub", 0755), 0);
		ASSERT_EQ(chown(V1ROOT "/sub/cgroup.procs", 1000, 1000), 0);
	} else {
		TH_LOG("no cgroup v1, that part is skipped");
	}

	/* Made by uid 1000, with the privilege the mount work takes. */
	ASSERT_EQ(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), 0);
	plain = fork();
	ASSERT_GE(plain, 0);
	if (!plain) {
		if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000) ||
		    drop_caps() || prctl(PR_SET_DUMPABLE, 1, 0, 0, 0))
			_exit(1);
		pause();
		_exit(0);
	}

	ASSERT_EQ(setresgid(-1, 1000, -1), 0);
	ASSERT_EQ(setresuid(-1, 1000, -1), 0);
	self->c.cfd = cell_create(CELL_SELF, 0);
	ASSERT_EQ(setresuid(-1, 0, -1), 0);
	ASSERT_EQ(setresgid(-1, 0, -1), 0);
	ASSERT_GE(self->c.cfd, 0);
	close(self->c.cfd);
	self->c.cfd = -1;

	/* cell_build() makes its own: do all of it as euid 1000. */
	prober = fork();
	ASSERT_GE(prober, 0);
	if (!prober) {
		struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3 };
		struct __user_cap_data_struct data[2];
		struct pollfd pfd = { .events = POLLIN };
		struct sched_param sp = { 0 };
		struct rlimit rl;
		struct cellctx c;
		cpu_set_t cpus;
		pid_t victim;
		char buf[32];
		int step;

		if (chown(CGROOT, 1000, 1000) || chown(CGROOT "/cgroup.procs", 1000, 1000))
			_exit(10);
		if (setgroups(2, (gid_t[]){ 2000, 2001 }))
			_exit(11);
		if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000))
			_exit(11);
		if (syscall(SYS_capget, &hdr, data))
			_exit(12);
		data[0].effective = data[0].permitted;
		data[1].effective = data[1].permitted;
		if (syscall(SYS_capset, &hdr, data))
			_exit(13);

		step = cell_build(&c, &(struct build){ .ids = 1 });
		if (step)
			_exit(20 + step);
		pidfd = spawn(c.cfd, &pid, "oneid", "1000", NULL);
		if (pidfd < 0)
			_exit(14);
		if (cell_wait(c.cfd))
			_exit(15);
		close(pidfd);
		cell_cleanup(&c);

		step = cell_build(&c, &(struct build){ .ids = 1 });
		if (step)
			_exit(50 + step);
		pidfd = spawn(c.cfd, &pid, "usr1", NULL, NULL);
		if (pidfd < 0)
			_exit(16);
		if (host_uid(pid) != 1000)
			_exit(17);

		/* Now be nobody in particular, with the very same uid. */
		if (drop_caps())
			_exit(18);
		if (kill(plain, 0))
			_exit(19);		/* an equal uid at home counts */
		if (kill(pid, 0) != -1 || errno != EPERM)
			_exit(2);
		if (kill(pid, SIGKILL) != -1 || errno != EPERM)
			_exit(3);
		if (setpriority(PRIO_PROCESS, pid, 5) != -1 || errno != EPERM)
			_exit(4);
		/* IOPRIO_WHO_PROCESS, IOPRIO_CLASS_IDLE */
		if (syscall(SYS_ioprio_set, 1, plain, 3 << 13))
			_exit(7);
		if (syscall(SYS_ioprio_set, 1, pid, 3 << 13) != -1 || errno != EPERM)
			_exit(8);
		CPU_ZERO(&cpus);
		CPU_SET(0, &cpus);
		if (sched_setaffinity(plain, sizeof(cpus), &cpus))
			_exit(100);
		if (sched_setaffinity(pid, sizeof(cpus), &cpus) != -1 || errno != EPERM)
			_exit(101);
		if (sched_setscheduler(plain, SCHED_BATCH, &sp))
			_exit(102);
		if (sched_setscheduler(pid, SCHED_BATCH, &sp) != -1 || errno != EPERM)
			_exit(103);
		if (prlimit(plain, RLIMIT_NOFILE, NULL, &rl))
			_exit(104);
		if (prlimit(pid, RLIMIT_NOFILE, NULL, &rl) != -1 || errno != EPERM)
			_exit(105);
		if (v1) {
			snprintf(buf, sizeof(buf), "%d", plain);
			if (write_file(V1ROOT "/sub/cgroup.procs", buf))
				_exit(106);
			snprintf(buf, sizeof(buf), "%d", pid);
			if (write_file(V1ROOT "/sub/cgroup.procs", buf) != -1 ||
			    errno != EACCES)
				_exit(107);
		}
		/* SIGIO: fatal at home, never sent across. It would end the cell. */
		victim = fork();
		if (victim < 0)
			_exit(108);
		if (!victim) {
			pause();
			_exit(0);
		}
		if (sigio_to(victim) || waitpid(victim, &step, 0) != victim ||
		    !WIFSIGNALED(step) || WTERMSIG(step) != SIGUSR1)
			_exit(109);
		if (sigio_to(pid))
			_exit(110);
		pfd.fd = pidfd;
		if (poll(&pfd, 1, 200) != 0)
			_exit(111);
		/*
		 * Last, since a traced task takes its signals differently. The
		 * capability LSM refuses this one too, for the user namespace.
		 */
		if (ptrace(PTRACE_SEIZE, plain, 0, 0))
			_exit(112);
		if (ptrace(PTRACE_SEIZE, pid, 0, 0) != -1 || errno != EPERM)
			_exit(113);
		/* The handle is what counts. */
		if (cell_configure(c.cfd, CELL_CMD_KILL, NULL, NULL, 0))
			_exit(5);
		if (cell_wait(c.cfd) != SIGKILL)
			_exit(6);
		_exit(0);
	}
	ASSERT_EQ(waitpid(prober, &status, 0), prober);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);

	kill(plain, SIGKILL);
	waitpid(plain, NULL, 0);
	if (v1) {
		EXPECT_EQ(rmdir(V1ROOT "/sub"), 0);
		EXPECT_EQ(umount(V1ROOT), 0);
	}
	rmdir(V1ROOT);
	EXPECT_EQ(chown(CGROOT, 0, 0), 0);
	EXPECT_EQ(chown(CGROOT "/cgroup.procs", 0, 0), 0);
}

/* The budget is judged against whoever fills the slot. */
TEST_F(cell, budget_takes_permission)
{
	int status;
	pid_t pid;

	ASSERT_EQ(mkdir(CGROOT "/notyours", 0755), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		int cfd, cg;

		if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000))
			_exit(1);
		cfd = cell_create(CELL_SELF, 0);
		if (cfd < 0)
			_exit(2);
		cg = open(CGROOT "/notyours", O_RDONLY | O_DIRECTORY);
		if (cg < 0)
			_exit(3);
		if (cell_configure(cfd, CELL_SET_FD, "budget", NULL, cg) != -1 ||
		    (errno != EPERM && errno != EACCES))
			_exit(4);
		_exit(0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
	rmdir(CGROOT "/notyours");
}

/* While it is built a cell can be configured from the inside of its network only. */
TEST_F(cell, entering_while_building)
{
	int fd, status;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true }), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		fd = cell_open(self->c.cfd, CELL_OPEN_SLOT, "pids", NULL, 0);
		if (fd < 0)
			_exit(1);
		/* Whoever got in could become the cell's init. */
		if (setns(fd, CLONE_NEWPID) != -1 || errno != EPERM)
			_exit(2);
		fd = cell_open(self->c.cfd, CELL_OPEN_SLOT, "net", NULL, 0);
		if (fd < 0)
			_exit(3);
		if (setns(fd, CLONE_NEWNET))
			_exit(4);
		_exit(0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

/* Root does not get a cell on kuid 0, least of all by default. */
TEST_F(cell, no_cell_on_uid_0)
{
	EXPECT_EQ(cell_build(&self->c, &(struct build){ .ids = 1 }), 4);
	EXPECT_EQ(errno, EPERM);
	cell_cleanup(&self->c);
	EXPECT_EQ(cell_build(&self->c, &(struct build){ .ids = 0 }), 18);
	EXPECT_EQ(errno, EPERM);
}

/* A kill takes everything in the budget with it, so a budget is one cell's. */
TEST_F(cell, budget_is_exclusive)
{
	char path[192], buf[32];
	int cfd, cg, status;
	struct stat st;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);

	cfd = cell_create(CELL_SELF, 0);
	ASSERT_GE(cfd, 0);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_FD, "budget", NULL, self->c.cgfd), -1);
	EXPECT_EQ(errno, EBUSY);

	/* Nor one that lies within. */
	snprintf(path, sizeof(path), "%s/sub", self->c.cg);
	ASSERT_EQ(mkdir(path, 0755), 0);
	cg = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(cg, 0);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_FD, "budget", NULL, cg), -1);
	EXPECT_EQ(errno, EBUSY);
	close(cg);

	/* Nor one that somebody is in. */
	ASSERT_EQ(mkdir(CGROOT "/busy", 0755), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		pause();
		_exit(0);
	}
	snprintf(buf, sizeof(buf), "%d", pid);
	ASSERT_EQ(write_file(CGROOT "/busy/cgroup.procs", buf), 0);
	cg = open(CGROOT "/busy", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(cg, 0);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_FD, "budget", NULL, cg), -1);
	EXPECT_EQ(errno, EBUSY);
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	close(cg);
	close(cfd);
	rmdir(CGROOT "/busy");

	/* It comes back when the cell is gone, with nothing of the cell's left. */
	ASSERT_EQ(cell_configure(self->c.cfd, CELL_CMD_KILL, NULL, NULL, 0), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	ASSERT_EQ(fstat(self->c.cgfd, &st), 0);
	EXPECT_EQ(st.st_uid, 0);
	ASSERT_EQ(fstatat(self->c.cgfd, "cgroup.procs", &st, 0), 0);
	EXPECT_EQ(st.st_uid, 0);
	EXPECT_EQ(access(path, F_OK), -1);
}

/* Making a mount namespace a cell's takes what entering it would take. */
TEST_F(cell, root_takes_permission)
{
	int nsfd, status;
	pid_t pid;

	nsfd = sys_open_tree(AT_FDCWD, "/tmp", OPEN_TREE_NAMESPACE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(nsfd, 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		int cfd;

		if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000))
			_exit(1);
		cfd = cell_create(CELL_SELF, 0);
		if (cfd < 0)
			_exit(2);
		if (cell_configure(cfd, CELL_SET_FD, "root", NULL, nsfd) != -1 || errno != EPERM)
			_exit(3);
		_exit(0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
	close(nsfd);
}

/* There are only so many blocks, and no one user gets them all. */
TEST_F(cell, blocks_are_counted)
{
	unsigned int ids = 65536;
	int a, b;

	ASSERT_EQ(write_file("/proc/sys/user/max_cell_id_blocks", "1"), 0);
	a = cell_create(CELL_SELF, 0);
	b = cell_create(CELL_SELF, 0);
	ASSERT_GE(a, 0);
	ASSERT_GE(b, 0);
	EXPECT_EQ(cell_configure(a, CELL_SET_BINARY, "ids", &ids, sizeof(ids)), 0);
	EXPECT_EQ(cell_configure(b, CELL_SET_BINARY, "ids", &ids, sizeof(ids)), -1);
	EXPECT_EQ(errno, ENOSPC);
	close(a);
	close(b);
	ASSERT_EQ(write_file("/proc/sys/user/max_cell_id_blocks", "4095"), 0);
}

static int mount_source(const char *fstype, const char *source, const char *opt,
			const char *val)
{
	int fs, mnt;

	fs = sys_fsopen(fstype, FSOPEN_CLOEXEC);
	if (fs < 0)
		return -1;
	if (sys_fsconfig(fs, FSCONFIG_SET_STRING, "source", source, 0) ||
	    (opt && sys_fsconfig(fs, FSCONFIG_SET_STRING, opt, val, 0)) ||
	    sys_fsconfig(fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0)) {
		close(fs);
		return -1;
	}
	mnt = sys_fsmount(fs, FSMOUNT_CLOEXEC, 0);
	close(fs);
	return mnt;
}

static int make_su(int dirfd)
{
	int fd = openat(dirfd, "su", O_CREAT | O_WRONLY, 0755);

	if (fd < 0 || fchmod(fd, 06755))
		return -1;
	close(fd);
	return 0;
}

/*
 * Dropping the bits changes the inode, so on a frozen filesystem the open has to
 * wait. Needs CELL_TEST_EXT4_IMG to name an ext4 image.
 */
TEST_F(cell, drop_privs_waits_for_thaw)
{
	const char *img = getenv("CELL_TEST_EXT4_IMG");
	int ctl, nr, loop, back, mnt, raw, pidfd;
	struct pollfd pfd;
	struct stat st;
	char dev[32];

	if (!img)
		SKIP(return, "CELL_TEST_EXT4_IMG is not set");
	ctl = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (ctl < 0)
		SKIP(return, "no loop devices");
	nr = ioctl(ctl, LOOP_CTL_GET_FREE);
	ASSERT_GE(nr, 0);
	snprintf(dev, sizeof(dev), "/dev/loop%d", nr);
	loop = open(dev, O_RDWR | O_CLOEXEC);
	back = open(img, O_RDWR | O_CLOEXEC);
	ASSERT_GE(loop, 0);
	ASSERT_GE(back, 0);
	ASSERT_EQ(ioctl(loop, LOOP_SET_FD, back), 0);

	mnt = mount_source("ext4", dev, NULL, NULL);
	ASSERT_GE(mnt, 0);
	ASSERT_EQ(make_su(mnt), 0);
	raw = sys_open_tree(mnt, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(raw, 0);
	raw = openat(raw, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(raw, 0);

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .data = mnt }), 0);
	ASSERT_EQ(ioctl(raw, FIFREEZE, 0), 0);

	pidfd = spawn(self->c.cfd, NULL, "data", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	pfd = (struct pollfd){ .fd = self->c.cfd, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 1500), 0);
	ASSERT_EQ(fstatat(raw, "su", &st, 0), 0);
	EXPECT_EQ(st.st_mode & 07777, 06755);

	ASSERT_EQ(ioctl(raw, FITHAW, 0), 0);
	EXPECT_EQ(cell_wait(self->c.cfd), 0);
	ASSERT_EQ(fstatat(raw, "su", &st, 0), 0);
	EXPECT_EQ(st.st_mode & 07777, 0755);

	close(pidfd);
	close(raw);
	close(mnt);
	cell_cleanup(&self->c);
	self->c.cfd = self->c.tree = self->c.raw = self->c.cgfd = -1;
	ioctl(loop, LOOP_CLR_FD, 0);
	close(loop);
	close(back);
	close(ctl);
}

/*
 * A filesystem with ->atomic_open() opens a file it creates with the directory
 * locked, a path tmpfs does not have. Needs CELL_TEST_9P_TAG to name a writable
 * 9p share over virtio.
 */
TEST_F(cell, drop_privs_with_atomic_open)
{
	const char *tag = getenv("CELL_TEST_9P_TAG");
	int status;
	pid_t pid;

	if (!tag)
		SKIP(return, "CELL_TEST_9P_TAG is not set");

	/* 9p cannot be idmapped, so a one-id cell, so not as root. */
	ASSERT_EQ(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3 };
		struct __user_cap_data_struct data[2];
		struct cellctx c;
		int mnt, pidfd, step;

		mnt = mount_source("9p", tag, "trans", "virtio");
		if (mnt < 0)
			_exit(77);
		if (fchmodat(mnt, "", 0777, AT_EMPTY_PATH) && errno != ENOTSUP && errno != EINVAL)
			_exit(9);
		if (chown(CGROOT, 1000, 1000) || chown(CGROOT "/cgroup.procs", 1000, 1000))
			_exit(10);
		if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000))
			_exit(11);
		if (syscall(SYS_capget, &hdr, data))
			_exit(12);
		data[0].effective = data[0].permitted;
		data[1].effective = data[1].permitted;
		if (syscall(SYS_capset, &hdr, data))
			_exit(13);
		unlinkat(mnt, "su", 0);
		if (make_su(mnt))
			_exit(14);

		step = cell_build(&c, &(struct build){ .ids = 1, .data = mnt });
		if (step)
			_exit(20 + step);
		pidfd = spawn(c.cfd, NULL, "data", "create", NULL);
		if (pidfd < 0)
			_exit(15);
		if (cell_wait(c.cfd))
			_exit(16);
		cell_cleanup(&c);
		_exit(0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(chown(CGROOT, 0, 0), 0);
	EXPECT_EQ(chown(CGROOT "/cgroup.procs", 0, 0), 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 77)
		SKIP(return, "cannot mount the 9p share");
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

/* Nothing but a spawn gets a task into a budget. */
TEST_F(cell, nothing_enters_the_budget)
{
	struct cell_clone_args ca = { .flags = CLONE_INTO_CGROUP, .exit_signal = SIGCHLD };
	char path[192], buf[32];
	int pidfd, vhost;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);

	snprintf(path, sizeof(path), "%s/cgroup.procs", self->c.cg);
	snprintf(buf, sizeof(buf), "%d", getpid());
	EXPECT_EQ(write_file(path, buf), -1);
	EXPECT_EQ(errno, EPERM);

	ca.cgroup = self->c.cgfd;
	pid = syscall(SYS_clone3, &ca, sizeof(ca));
	if (!pid)
		_exit(0);
	EXPECT_EQ(pid, -1);
	EXPECT_EQ(errno, EPERM);

	/* Nor the kernel on behalf of a task of the cell. */
	vhost = open("/dev/vhost-net", O_RDWR | O_CLOEXEC);
	if (vhost < 0) {
		TH_LOG("no /dev/vhost-net, that part is skipped");
		return;
	}
	pidfd = prepare(self->c.cfd, NULL, "vhost", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(task_configure(pidfd, TASK_SET_FD, "3", NULL, vhost), 0);
	ASSERT_EQ(task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0), 0);
	/* With the device still open out here, the cell gets to be DEAD. */
	EXPECT_EQ(cell_wait(self->c.cfd), 0);
	EXPECT_EQ(cg_populated(self->c.cg), 0);
	close(vhost);
	close(pidfd);
}

/* A mount that was idmapped for a cell names its ids, so it holds on to them. */
TEST_F(cell, idmapped_mount_pins_the_block)
{
	struct mount_attr attr = { .attr_set = MOUNT_ATTR_IDMAP };
	unsigned int ids = 65536;
	int a, b, mnt, i, ret = -1;

	ASSERT_EQ(write_file("/proc/sys/user/max_cell_id_blocks", "1"), 0);
	a = cell_create(CELL_SELF, 0);
	ASSERT_GE(a, 0);
	ASSERT_EQ(cell_configure(a, CELL_SET_BINARY, "ids", &ids, sizeof(ids)), 0);
	mnt = new_tmpfs();
	ASSERT_GE(mnt, 0);
	attr.userns_fd = a;
	ASSERT_EQ(sys_mount_setattr(mnt, "", AT_EMPTY_PATH, &attr, sizeof(attr)), 0);

	/* The cell is gone. The mount is not. */
	ASSERT_EQ(cell_configure(a, CELL_CMD_KILL, NULL, NULL, 0), 0);
	close(a);
	usleep(500000);
	b = cell_create(CELL_SELF, 0);
	ASSERT_GE(b, 0);
	EXPECT_EQ(cell_configure(b, CELL_SET_BINARY, "ids", &ids, sizeof(ids)), -1);
	EXPECT_EQ(errno, ENOSPC);

	close(mnt);
	for (i = 0; i < 100 && ret; i++) {
		usleep(50000);
		ret = cell_configure(b, CELL_SET_BINARY, "ids", &ids, sizeof(ids));
	}
	EXPECT_EQ(ret, 0);
	close(b);
	ASSERT_EQ(write_file("/proc/sys/user/max_cell_id_blocks", "4095"), 0);
}

/* The window is the kernel's. A one-id cell is not made of an id in it. */
TEST_F(cell, no_cell_on_an_id_of_the_window)
{
	int status;
	pid_t pid;

	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		unsigned int ids = 1;
		int cfd;

		if (setresuid(CELL_WINDOW_FIRST + 0x1234, CELL_WINDOW_FIRST + 0x1234, -1))
			_exit(1);
		cfd = cell_create(CELL_SELF, 0);
		if (cfd < 0)
			_exit(2);
		if (cell_configure(cfd, CELL_SET_BINARY, "ids", &ids, sizeof(ids)) != -1 ||
		    errno != EPERM)
			_exit(3);
		_exit(0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

/* Send @fd over @sock, by SCM_RIGHTS. */
static int send_one_fd(int sock, int fd)
{
	char buf[CMSG_SPACE(sizeof(int))] = {};
	struct iovec iov = { .iov_base = "x", .iov_len = 1 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = buf, .msg_controllen = sizeof(buf),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}

/*
 * A socket that was to go to a task which then never started is nobody's but
 * the host's, and goes on working as it did.
 */
TEST_F(cell, failed_start_leaves_a_socket_alone)
{
	int sp[2], pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp), 0);
	ASSERT_EQ(send_one_fd(sp[0], sp[0]), 0);

	pidfd = prepare(self->c.cfd, NULL, "exit", "0", NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(task_configure(pidfd, TASK_SET_FD, "3", NULL, sp[1]), 0);
	ASSERT_EQ(task_configure(pidfd, TASK_SET_STRING, "exec", "/no-such-file", 0), 0);
	ASSERT_EQ(task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0), -1);
	ASSERT_EQ(errno, ENOENT);
	close(pidfd);

	EXPECT_EQ(send_one_fd(sp[0], sp[0]), 0);
	close(sp[0]);
	close(sp[1]);
}

/*
 * A network namespace can be shared with a cell, but not that of another cell,
 * whose tasks have every capability over it. Not while that one is still being
 * built either: a slot outlives that.
 */
TEST_F(cell, no_net_of_another_cell)
{
	char path[64];
	int a, b, nsfd;
	pid_t pid;

	/* Of a cell that is being built. */
	b = cell_create(CELL_SELF, 0);
	ASSERT_GE(b, 0);
	ASSERT_EQ(cell_configure(b, CELL_SET_STRING, "net", "new", 0), 0);
	nsfd = cell_open(b, CELL_OPEN_SLOT, "net", NULL, 0);
	ASSERT_GE(nsfd, 0);
	a = cell_create(CELL_SELF, 0);
	ASSERT_GE(a, 0);
	EXPECT_EQ(cell_configure(a, CELL_SET_FD, "net", NULL, nsfd), -1);
	EXPECT_EQ(errno, EPERM);
	close(nsfd);
	close(a);
	close(b);

	/* Of one that is running. */
	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	ASSERT_GE(spawn(self->c.cfd, &pid, "pause", NULL, NULL), 0);
	snprintf(path, sizeof(path), "/proc/%d/ns/net", pid);
	nsfd = open(path, O_RDONLY | O_CLOEXEC);
	ASSERT_GE(nsfd, 0);
	a = cell_create(CELL_SELF, 0);
	ASSERT_GE(a, 0);
	EXPECT_EQ(cell_configure(a, CELL_SET_FD, "net", NULL, nsfd), -1);
	EXPECT_EQ(errno, EPERM);
	close(nsfd);

	/* The caller's own is fine. */
	nsfd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(nsfd, 0);
	EXPECT_EQ(cell_configure(a, CELL_SET_FD, "net", NULL, nsfd), 0);
	close(nsfd);
	close(a);
}

/* The name is taken, and there is nothing to fill the slot with yet. */
TEST_F(cell, spawn_slot_is_reserved)
{
	unsigned int one = 1;
	int cfd;

	cfd = cell_create(CELL_SELF, 0);
	ASSERT_GE(cfd, 0);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_FLAG, "spawn", NULL, 0), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_STRING, "spawn", "yes", 0), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_BINARY, "spawn", &one, sizeof(one)), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_FD, "spawn", NULL, cfd), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
	close(cfd);
}

/*
 * Nobody in particular builds a cell. The mount work takes a user namespace and
 * a mount namespace of one's own, and nothing else.
 */
TEST_F(cell, unprivileged_builder)
{
	int status;
	pid_t pid;

	ASSERT_EQ(chown(CGROOT, 1000, 1000), 0);
	ASSERT_EQ(chown(CGROOT "/cgroup.procs", 1000, 1000), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		struct cellctx c;
		int step;

		/* Dumpable, or /proc/self is root's. */
		if (setgroups(0, NULL) || setresgid(1000, 1000, 1000) ||
		    setresuid(1000, 1000, 1000) ||
		    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0))
			_exit(1);
		if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
			_exit(2);
		if (write_file("/proc/self/setgroups", "deny") ||
		    write_file("/proc/self/uid_map", "1000 1000 1") ||
		    write_file("/proc/self/gid_map", "1000 1000 1"))
			_exit(3);
		step = cell_build(&c, &(struct build){ .ids = 1 });
		if (step)
			_exit(20 + step);
		if (spawn(c.cfd, NULL, "exit", "0", NULL) < 0)
			_exit(4);
		_exit(cell_wait(c.cfd) ? 5 : 0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
	EXPECT_EQ(chown(CGROOT, 0, 0), 0);
	EXPECT_EQ(chown(CGROOT "/cgroup.procs", 0, 0), 0);
}

/* From here on system call @nr fails with EACCES, for the caller and its issue. */
static int seccomp_deny(int nr)
{
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = ARRAY_SIZE(insns), .filter = insns };

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -1;
	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

/* What a confined task spawns is confined as it is itself. */
TEST_F(cell, seccomp_filters_are_inherited)
{
	int status;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		if (seccomp_deny(SYS_getrusage))
			_exit(1);
		if (spawn(self->c.cfd, NULL, "seccomp", NULL, NULL) < 0)
			_exit(2);
		_exit(cell_wait(self->c.cfd) ? 3 : 0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

/*
 * A listener on a filter stays with the spawner, outside. It can answer for the
 * system calls of a task of the cell. It cannot put a file into it.
 */
TEST_F(cell, seccomp_listener_adds_no_file)
{
	int status;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		struct sock_filter insns[] = {
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getrusage, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		};
		struct sock_fprog prog = { .len = ARRAY_SIZE(insns), .filter = insns };
		struct seccomp_notif_addfd addfd = {};
		struct seccomp_notif_resp resp = {};
		struct seccomp_notif req = {};
		int listener, round;
		pid_t home;

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			_exit(1);
		listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
				   SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
		if (listener < 0)
			_exit(2);

		/* First at home, where it works, then into the cell. */
		for (round = 0; round < 2; round++) {
			if (!round) {
				home = fork();
				if (home < 0)
					_exit(3);
				if (!home) {
					struct rusage ru;

					_exit(getrusage(RUSAGE_SELF, &ru) == -1 &&
					      errno == EACCES ? 0 : 1);
				}
			} else if (spawn(self->c.cfd, NULL, "seccomp", NULL, NULL) < 0) {
				_exit(4);
			}

			memset(&req, 0, sizeof(req));
			if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req))
				_exit(5);
			addfd.id = req.id;
			addfd.srcfd = self->c.cfd;
			if (!round) {
				if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) < 0)
					_exit(6);
			} else if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) != -1 ||
				   errno != EPERM) {
				_exit(7);
			}
			resp.id = req.id;
			resp.error = -EACCES;
			if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp))
				_exit(8);
			if (!round && (waitpid(home, &status, 0) != home || status))
				_exit(9);
		}
		_exit(cell_wait(self->c.cfd) ? 10 : 0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

static void no_handler(int sig)
{
}

/* Nothing is inherited: not what the spawner ignores, handles or blocks. */
TEST_F(cell, signals_start_from_scratch)
{
	int status;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		sigset_t set;

		signal(SIGPIPE, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);
		signal(SIGUSR2, no_handler);
		sigemptyset(&set);
		sigaddset(&set, SIGUSR1);
		sigaddset(&set, SIGTERM);
		if (sigprocmask(SIG_BLOCK, &set, NULL) || raise(SIGUSR1))
			_exit(1);
		if (spawn(self->c.cfd, NULL, "signals", NULL, NULL) < 0)
			_exit(2);
		_exit(cell_wait(self->c.cfd) ? 3 : 0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

/* A hard boundary: the uid of root on the host counts for no more than any other. */
TEST_F(cell, uid_0_means_nothing_either)
{
	struct pollfd pfd = { .events = POLLIN };
	char buf[32];
	int ready[2];
	pid_t pid;
	bool v1;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	ASSERT_EQ(pipe(ready), 0);
	pfd.fd = prepare(self->c.cfd, &pid, "usr1", NULL, NULL);
	ASSERT_GE(pfd.fd, 0);
	ASSERT_EQ(task_configure(pfd.fd, TASK_SET_FD, "3", NULL, ready[1]), 0);
	ASSERT_EQ(task_configure(pfd.fd, TASK_CMD_START, NULL, NULL, 0), 0);
	close(ready[1]);
	/* Until it has its handler an init does not get the signal anyway. */
	ASSERT_EQ(read(ready[0], buf, 1), 1);
	close(ready[0]);

	/* It would end the cell. */
	ASSERT_EQ(sigio_to(pid), 0);
	EXPECT_EQ(poll(&pfd, 1, 200), 0);

	mkdir(V1ROOT, 0755);
	v1 = !mount("none", V1ROOT, "cgroup", 0, "none,name=celltest");
	if (v1) {
		ASSERT_EQ(mkdir(V1ROOT "/sub", 0755), 0);
		snprintf(buf, sizeof(buf), "%d", pid);
		EXPECT_EQ(write_file(V1ROOT "/sub/cgroup.procs", buf), -1);
		EXPECT_EQ(errno, EACCES);
		EXPECT_EQ(rmdir(V1ROOT "/sub"), 0);
		EXPECT_EQ(umount(V1ROOT), 0);
	} else {
		TH_LOG("no cgroup v1, that part is skipped");
	}
	rmdir(V1ROOT);
	close(pfd.fd);
}

/* The exec of an embryo is no system call. This is how a filter prevents it. */
TEST_F(cell, seccomp_can_deny_a_start)
{
	int status;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		if (seccomp_deny(__NR_task_configure))
			_exit(1);
		if (spawn(self->c.cfd, NULL, "exit", "0", NULL) >= 0)
			_exit(2);
		_exit(errno == EACCES ? 0 : 3);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
	/* Nothing ever ran. */
	EXPECT_EQ(cg_populated(self->c.cg), 0);
}

/*
 * DEAD means gone. The init of a cell is still on its way out when the kernel
 * learns of its exit, and the cell must not be reported dead before it is off
 * the cpu for good: that is when it stops counting for cgroup.events.
 */
TEST_F(cell, dead_means_gone)
{
	int i, pidfd, early = 0;

	for (i = 0; i < 60; i++) {
		struct cellctx c;

		ASSERT_EQ(cell_build(&c, &(struct build){ .ids = 65536 }), 0);
		pidfd = spawn(c.cfd, NULL, "exit", "0", NULL);
		ASSERT_GE(pidfd, 0);
		ASSERT_EQ(cell_wait(c.cfd), 0);
		if (cg_populated(c.cg))
			early++;
		close(pidfd);
		cell_cleanup(&c);
	}
	EXPECT_EQ(early, 0);
}

/* Make and break a good many, so that leaks and races get a chance. */
TEST_F(cell, churn)
{
	int i;

	for (i = 0; i < 40; i++) {
		struct cellctx c;
		int pidfd;

		ASSERT_EQ(cell_build(&c, &(struct build){ .ids = 65536 }), 0);
		pidfd = spawn(c.cfd, NULL, i % 3 ? "pause" : "exit", "0", NULL);
		ASSERT_GE(pidfd, 0);
		if (i % 5 == 0) {
			int second = prepare(c.cfd, NULL, "pause", NULL, NULL);

			if (second >= 0)
				close(second);
		}
		close(pidfd);
		cell_cleanup(&c);
	}
}

/* A kill against spawns in flight: whatever got in is gone when it says DEAD. */
TEST_F(cell, kill_races_with_spawn)
{
	int i, j;

	for (i = 0; i < 25; i++) {
		pid_t spawners[3];
		struct cellctx c;
		int pidfd;

		ASSERT_EQ(cell_build(&c, &(struct build){ .ids = 65536 }), 0);
		pidfd = spawn(c.cfd, NULL, "pause", NULL, NULL);
		ASSERT_GE(pidfd, 0);

		for (j = 0; j < 3; j++) {
			spawners[j] = fork();
			ASSERT_GE(spawners[j], 0);
			if (!spawners[j]) {
				for (;;) {
					int p = j ? spawn(c.cfd, NULL, "pause", NULL, NULL) :
						    prepare(c.cfd, NULL, "pause", NULL, NULL);

					if (p < 0)
						_exit(errno == ESRCH || errno == ENOMEM ||
						      errno == EINTR || errno == EBUSY ?
						      0 : 1);
					close(p);
				}
			}
		}
		usleep(1000 * (i % 7) * (i % 5));
		ASSERT_EQ(cell_configure(c.cfd, CELL_CMD_KILL, NULL, NULL, 0), 0);
		EXPECT_EQ(cell_wait(c.cfd), SIGKILL);
		EXPECT_EQ(cg_populated(c.cg), 0);
		for (j = 0; j < 3; j++) {
			int status;

			ASSERT_EQ(waitpid(spawners[j], &status, 0), spawners[j]);
			EXPECT_EQ(status, 0);
		}
		EXPECT_EQ(cg_populated(c.cg), 0);
		close(pidfd);
		cell_cleanup(&c);
	}
}

/* Starting an embryo while its handle goes away, from two processes. */
TEST_F(cell, start_races_with_close)
{
	int i;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	ASSERT_GE(spawn(self->c.cfd, NULL, "pause", NULL, NULL), 0);

	for (i = 0; i < 60; i++) {
		int pidfd = prepare(self->c.cfd, NULL, "exit", "0", NULL);
		int status;
		pid_t pid;

		ASSERT_GE(pidfd, 0);
		pid = fork();
		ASSERT_GE(pid, 0);
		if (!pid) {
			/* Both hold the one file. Only one start can win. */
			int r = task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0);

			_exit(!r || errno == EBUSY || errno == ESRCH ? 0 : 1);
		}
		if (i & 1)
			task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0);
		close(pidfd);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		EXPECT_EQ(status, 0);
	}
	EXPECT_EQ(cell_state(self->c.cfd), CELL_RUNNING);
}

/* The last handle going away against everything else. */
TEST_F(cell, close_races)
{
	int i;

	for (i = 0; i < 40; i++) {
		struct cellctx c;
		int status;
		pid_t pid;

		ASSERT_EQ(cell_build(&c, &(struct build){ .ids = 65536, .no_seal = i % 4 == 0 }), 0);
		pid = fork();
		ASSERT_GE(pid, 0);
		if (!pid) {
			int p = spawn(c.cfd, NULL, i % 3 ? "pause" : "exit", "0", NULL);

			if (p >= 0)
				close(p);
			_exit(0);		/* drops its copy of the handle */
		}
		if (i % 2)
			usleep(500 * (i % 9));
		close(c.cfd);
		c.cfd = -1;
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		cell_cleanup(&c);
		EXPECT_EQ(access(c.cg, F_OK), -1);
	}
}

TEST_HARNESS_MAIN
