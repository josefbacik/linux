// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for cells, the slots: what may fill them, who may fill them, and what
 * sealing makes of them.
 */
#include "cell_test.h"

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

/* Making a mount namespace a cell's takes CAP_SYS_ADMIN over its owner. */
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

/*
 * Sharing a network namespace takes CAP_SYS_ADMIN over its owner, which is half
 * of what setns() asks for. The other half is about the namespaces of the
 * caller, and those do not change. So a caller without any privilege can share
 * what a child of its made in a user namespace of its own, and cannot enter it.
 */
TEST_F(cell, net_takes_half_of_setns)
{
	int status;
	pid_t pid;

	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		int ready[2], hold[2], cfd, nsfd, host;
		char path[64], c;
		pid_t child;

		host = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
		if (host < 0 || setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000))
			_exit(1);
		/* /proc/<pid>/ns of the child is gated by ptrace access. */
		if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) || pipe(ready) || pipe(hold))
			_exit(2);
		child = fork();
		if (child < 0)
			_exit(3);
		if (!child) {
			close(hold[1]);
			if (unshare(CLONE_NEWUSER | CLONE_NEWNET) || write(ready[1], "r", 1) != 1)
				_exit(1);
			_exit(read(hold[0], &c, 1));
		}
		if (read(ready[0], &c, 1) != 1)
			_exit(4);
		snprintf(path, sizeof(path), "/proc/%d/ns/net", child);
		nsfd = open(path, O_RDONLY | O_CLOEXEC);
		if (nsfd < 0)
			_exit(5);
		if (setns(nsfd, CLONE_NEWNET) != -1 || errno != EPERM)
			_exit(6);
		cfd = cell_create(CELL_SELF, 0);
		if (cfd < 0)
			_exit(7);
		/* Not the host's, over whose owner it has nothing. */
		if (cell_configure(cfd, CELL_SET_FD, "net", NULL, host) != -1 || errno != EPERM)
			_exit(8);
		if (cell_configure(cfd, CELL_SET_FD, "net", NULL, nsfd))
			_exit(9);
		close(hold[1]);
		_exit(waitpid(child, &status, 0) == child && !status ? 0 : 10);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

/*
 * A network namespace can be shared with a cell, but not one that another cell
 * owns, whose tasks have every capability over it. Not while that one is still
 * being built either: a slot outlives that.
 */
TEST_F(cell, no_net_of_another_cell)
{
	char path[64];
	int a, b, nsfd;
	pid_t pid;

	/* Of a cell that is being built. */
	b = cell_create(CELL_SELF, 0);
	ASSERT_GE(b, 0);
	ASSERT_EQ(cell_configure(b, CELL_SET_STRING, "net", "own", 0), 0);
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
	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .net_str = "own" }), 0);
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

/* A network namespace of the caller's own making, with lo up. */
static int new_netns(void)
{
	struct ifreq ifr = { .ifr_name = "lo", .ifr_flags = IFF_UP };
	int old, new = -1, sock;

	old = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (old < 0 || unshare(CLONE_NEWNET))
		return -1;
	sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock >= 0 && !ioctl(sock, SIOCSIFFLAGS, &ifr))
		new = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	close(sock);
	if (setns(old, CLONE_NEWNET))
		return -1;
	close(old);
	return new;
}

/*
 * A pod is several cells and not one. Each has a tree, ids and a budget of its
 * own. What they share is filled in from the same file descriptors: a network
 * namespace that the builder made and still owns, and a volume. One that shows
 * up later is one more cell. Nothing enters anything.
 */
TEST_F(cell, pod)
{
	int net, vol, vol_a, vol_b, old, ready[2], pidfd;
	struct cellctx b;
	char c;

	net = new_netns();
	ASSERT_GE(net, 0);
	vol = new_tmpfs();
	ASSERT_GE(vol, 0);
	vol_a = sys_open_tree(vol, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	vol_b = sys_open_tree(vol, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(vol_a, 0);
	ASSERT_GE(vol_b, 0);

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .net = net,
							.data = vol_a }), 0);
	ASSERT_EQ(pipe2(ready, O_CLOEXEC), 0);
	pidfd = prepare(self->c.cfd, "pod-serve", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, ready[1]), 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);
	close(pidfd);
	close(ready[1]);
	ASSERT_EQ(read(ready[0], &c, 1), 1);

	/* The second one is made while the first is running. */
	ASSERT_EQ(cell_build(&b, &(struct build){ .ids = 65536, .net = net,
						  .data = vol_b }), 0);

	/* The builder owns the network namespace, so it can still get in there. */
	old = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(old, 0);
	EXPECT_EQ(setns(net, CLONE_NEWNET), 0);
	ASSERT_EQ(setns(old, CLONE_NEWNET), 0);
	close(old);

	pidfd = spawn(b.cfd, NULL, "pod-connect", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	close(pidfd);
	EXPECT_EQ(cell_wait_dead(b.cfd), 0);
	EXPECT_EQ(cell_wait_dead(self->c.cfd), 0);

	cell_cleanup(&b);
	close(ready[0]);
	close(net);
	close(vol);
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
	ASSERT_EQ(cell_kill(self->c.cfd, 0), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	ASSERT_EQ(fstat(self->c.cgfd, &st), 0);
	EXPECT_EQ(st.st_uid, 0);
	ASSERT_EQ(fstatat(self->c.cgfd, "cgroup.procs", &st, 0), 0);
	EXPECT_EQ(st.st_uid, 0);
	EXPECT_EQ(access(path, F_OK), -1);
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
	pidfd = prepare(self->c.cfd, "vhost", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, vhost), 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);
	/* With the device still open out here, the cell gets to be DEAD. */
	EXPECT_EQ(cell_wait(self->c.cfd), 0);
	EXPECT_EQ(cg_populated(self->c.cg), 0);
	close(vhost);
	close(pidfd);
}

/*
 * Nobody in particular builds a cell. The mount work takes a user namespace and
 * a mount namespace of one's own, and nothing else.
 */
/*
 * A task of a cell changes nothing in cgroupfs outside of its budget, even if the
 * builder gave it all of cgroupfs and somebody left a cgroup open to anybody.
 * Enabling a controller makes files in the children that belong to whoever asked,
 * and nothing asks whether their id can be stored: it would outlive the cell.
 */
TEST_F(cell, changes_nothing_outside_its_budget)
{
	struct stat st;
	int pidfd;
	char c = 0;

	write_file(CGROOT "/cgroup.subtree_control", "+pids");
	ASSERT_EQ(mkdir(CGROOT "/open", 0777), 0);
	ASSERT_EQ(chmod(CGROOT "/open", 0777), 0);
	ASSERT_EQ(chmod(CGROOT "/open/cgroup.subtree_control", 0666), 0);
	ASSERT_EQ(chmod(CGROOT "/open/cgroup.procs", 0666), 0);
	chmod(CGROOT "/open/pids.max", 0666);
	ASSERT_EQ(mkdir(CGROOT "/open/kid", 0755), 0);
	ASSERT_EQ(mkdir(CGROOT "/open/empty", 0755), 0);
	ASSERT_EQ(setxattr(CGROOT "/open", "user.host", "h", 1, 0), 0);

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .cgroupfs = true }), 0);
	pidfd = spawn(self->c.cfd, NULL, "outside", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	EXPECT_EQ(cell_wait_dead(self->c.cfd), 0);
	close(pidfd);

	/* Nothing was made, so nothing is left that is owned by an id of the cell. */
	EXPECT_EQ(stat(CGROOT "/open/kid/pids.max", &st), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(stat(CGROOT "/open/empty", &st), 0);
	EXPECT_EQ(getxattr(CGROOT "/open", "user.host", &c, 1), 1);
	EXPECT_EQ(c, 'h');
	EXPECT_EQ(getxattr(CGROOT "/open", "user.cell", &c, 1), -1);

	write_file(CGROOT "/open/cgroup.subtree_control", "-pids");
	rmdir(CGROOT "/open/kid");
	rmdir(CGROOT "/open/empty");
	rmdir(CGROOT "/open");
}

#define V1ROOT	"/tmp/cell-test-v1"

TEST_F(cell, changes_nothing_on_a_legacy_hierarchy)
{
	struct stat st;
	int pidfd;

	mkdir(V1ROOT, 0755);
	if (mount("none", V1ROOT, "cgroup", 0, "none,name=celltest")) {
		rmdir(V1ROOT);
		SKIP(return, "no legacy hierarchies");
	}
	ASSERT_EQ(mkdir(V1ROOT "/open", 0777), 0);
	ASSERT_EQ(chmod(V1ROOT "/open", 0777), 0);
	ASSERT_EQ(chmod(V1ROOT "/open/cgroup.procs", 0666), 0);
	ASSERT_EQ(chmod(V1ROOT "/open/notify_on_release", 0666), 0);
	ASSERT_EQ(mkdir(V1ROOT "/open/empty", 0777), 0);

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .bind = V1ROOT }), 0);
	pidfd = spawn(self->c.cfd, NULL, "legacy", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	EXPECT_EQ(cell_wait_dead(self->c.cfd), 0);
	close(pidfd);
	EXPECT_EQ(stat(V1ROOT "/open/empty", &st), 0);

	cell_cleanup(&self->c);
	self->c.cfd = self->c.tree = self->c.raw = self->c.cgfd = -1;
	rmdir(V1ROOT "/open/other");
	rmdir(V1ROOT "/open/empty");
	EXPECT_EQ(rmdir(V1ROOT "/open"), 0);
	EXPECT_EQ(umount(V1ROOT), 0);
	rmdir(V1ROOT);
}

/* Nor does it help to own the cgroup, as a cell of one id does what its maker owns. */
TEST_F(cell, changes_nothing_outside_its_budget_that_it_owns)
{
	struct stat st;
	int status;
	pid_t pid;
	char c = 0;
	bool v1;

	ASSERT_EQ(chown(CGROOT, 1000, 1000), 0);
	ASSERT_EQ(chown(CGROOT "/cgroup.procs", 1000, 1000), 0);
	ASSERT_EQ(mkdir(CGROOT "/theirs", 0755), 0);
	ASSERT_EQ(mkdir(CGROOT "/theirs/empty", 0755), 0);
	ASSERT_EQ(chown(CGROOT "/theirs", 1000, 1000), 0);
	ASSERT_EQ(chown(CGROOT "/theirs/empty", 1000, 1000), 0);
	ASSERT_EQ(chown(CGROOT "/theirs/cgroup.procs", 1000, 1000), 0);
	ASSERT_EQ(chown(CGROOT "/theirs/cgroup.max.depth", 1000, 1000), 0);
	ASSERT_EQ(setxattr(CGROOT "/theirs", "user.host", "h", 1, 0), 0);
	mkdir(V1ROOT, 0755);
	v1 = !mount("none", V1ROOT, "cgroup", 0, "none,name=celltest");
	if (v1) {
		ASSERT_EQ(mkdir(V1ROOT "/theirs", 0755), 0);
		ASSERT_EQ(mkdir(V1ROOT "/theirs/empty", 0755), 0);
		ASSERT_EQ(chown(V1ROOT "/theirs", 1000, 1000), 0);
		ASSERT_EQ(chown(V1ROOT "/theirs/empty", 1000, 1000), 0);
	}
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		struct cellctx c;
		int step, pidfd, dir, procs, legacy;

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
		dir = open(CGROOT "/theirs", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		/* Not cgroup.procs, which has more reasons to refuse. */
		procs = open(CGROOT "/theirs/cgroup.max.depth", O_WRONLY | O_CLOEXEC);
		pidfd = prepare(c.cfd, "outside-own", NULL, NULL);
		if (dir < 0 || procs < 0 || pidfd < 0 ||
		    pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, dir) ||
		    pidfd_configure(pidfd, PIDFD_SET_FD, "4", NULL, procs))
			_exit(4);
		legacy = open(V1ROOT "/theirs", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (v1 && (legacy < 0 ||
			   pidfd_configure(pidfd, PIDFD_SET_FD, "5", NULL, legacy)))
			_exit(6);
		if (pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0))
			_exit(7);
		_exit(cell_wait(c.cfd) ? 5 : 0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);

	EXPECT_EQ(stat(CGROOT "/theirs", &st), 0);
	EXPECT_EQ(st.st_mode & 07777, 0755);
	EXPECT_EQ(stat(CGROOT "/theirs/empty", &st), 0);
	EXPECT_EQ(getxattr(CGROOT "/theirs", "user.host", &c, 1), 1);
	EXPECT_EQ(getxattr(CGROOT "/theirs", "user.cell", &c, 1), -1);

	if (v1) {
		EXPECT_EQ(stat(V1ROOT "/theirs/empty", &st), 0);
		rmdir(V1ROOT "/theirs/other");
		rmdir(V1ROOT "/theirs/mine");
		rmdir(V1ROOT "/theirs/empty");
		EXPECT_EQ(rmdir(V1ROOT "/theirs"), 0);
		EXPECT_EQ(umount(V1ROOT), 0);
	}
	rmdir(V1ROOT);
	rmdir(CGROOT "/theirs/mine");
	rmdir(CGROOT "/theirs/empty");
	EXPECT_EQ(rmdir(CGROOT "/theirs"), 0);
	EXPECT_EQ(chown(CGROOT, 0, 0), 0);
	EXPECT_EQ(chown(CGROOT "/cgroup.procs", 0, 0), 0);
}

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

TEST_HARNESS_MAIN
