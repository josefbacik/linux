// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for cells, the boundary: nobody enters, a uid means nothing across it,
 * and sockets carry bytes.
 */
#include "cell_test.h"

TEST_F(cell, membership)
{
	RUN_IN_CELL("membership");
}

TEST_F(cell, nobody_enters)
{
	static const char * const ns[] = { "user", "mnt", "pid", "net", "ipc", "uts", "cgroup" };
	char path[64];
	unsigned int i;
	pid_t pid;
	int pidfd, fd;

	/* With a network namespace that is the cell's as well. */
	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .net_str = "own" }), 0);
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

/* While it is built a cell can be configured from the inside of its network only. */
TEST_F(cell, entering_while_building)
{
	int fd, status;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true,
							.net_str = "own" }), 0);
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
		if (cell_kill(c.cfd, 0))
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
	pfd.fd = prepare(self->c.cfd, "usr1", NULL, NULL);
	ASSERT_GE(pfd.fd, 0);
	ASSERT_EQ(pidfd_configure(pfd.fd, PIDFD_SET_FD, "3", NULL, ready[1]), 0);
	ASSERT_EQ(pidfd_configure(pfd.fd, PIDFD_CMD_START, NULL, NULL, 0), 0);
	pid = pidfd_nr(pfd.fd);
	ASSERT_GT(pid, 0);
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
	pidfd = prepare(self->c.cfd, "unix", NULL, NULL);
	ASSERT_GE(pidfd, 0);

	/* A file in flight from before the socket is given away. */
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &zero, sizeof(int));
	c = 'q';
	ASSERT_EQ(sendmsg(sv[0], &msg, 0), 1);
	c = 'h';

	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, sv[1]), 0);
	close(sv[1]);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);

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

/* See check_peer_race(). */
TEST_F(cell, peer_is_checked_and_read_at_once)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int lsock, cwd, pidfd, status;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true }), 0);
	lsock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	ASSERT_GE(lsock, 0);
	cwd = open(".", O_RDONLY | O_DIRECTORY);
	ASSERT_EQ(fchdir(self->c.raw), 0);
	strcpy(addr.sun_path, "tmp/sock");
	ASSERT_EQ(bind(lsock, (struct sockaddr *)&addr, sizeof(addr)), 0);
	ASSERT_EQ(chmod("tmp/sock", 0777), 0);
	ASSERT_EQ(fchdir(cwd), 0);
	close(cwd);
	ASSERT_EQ(listen(lsock, 128), 0);
	ASSERT_EQ(cell_configure(self->c.cfd, CELL_CMD_SEAL, NULL, NULL, 0), 0);

	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		for (;;) {
			int conn = accept(lsock, NULL, NULL);

			if (conn >= 0)
				close(conn);
		}
	}
	pidfd = spawn(self->c.cfd, NULL, "peer-race", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	EXPECT_EQ(cell_wait(self->c.cfd), 0);
	close(pidfd);
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	close(lsock);
}

TEST_HARNESS_MAIN
