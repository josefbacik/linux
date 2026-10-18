// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for cells, spawning: empty pidfds, and what a new task does and does
 * not start out with.
 */
#include "cell_test.h"

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

/* What pidfd_open() takes with PIDFD_EMPTY. */
TEST_F(cell, empty_pidfd_open)
{
	int fd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);

	/* Outside of a cell it makes sense, and is not done yet. */
	EXPECT_EQ(pidfd_open_empty(-EBADF, 0), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
	EXPECT_EQ(pidfd_open_empty(-1, 0), -1);
	EXPECT_EQ(errno, EBADF);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	EXPECT_EQ(pidfd_open_empty(fd, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	close(fd);
	EXPECT_EQ(pidfd_open_empty(self->c.cfd, O_EXCL /* PIDFD_THREAD */), -1);
	EXPECT_EQ(errno, EINVAL);

	fd = pidfd_open_empty(self->c.cfd, 0);
	ASSERT_GE(fd, 0);
	EXPECT_EQ(fcntl(fd, F_GETFD), FD_CLOEXEC);
	close(fd);
	/* Nothing came of it, and the cell is none the worse. */
	EXPECT_EQ(cell_state(self->c.cfd), CELL_SEALED);
}

/* The "Pid:" line of the fdinfo of a pidfd, or -2. */
static int pidfd_fdinfo_pid(int pidfd)
{
	char path[64], line[128];
	int nr = -2;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
	f = fopen(path, "r");
	if (!f)
		return -2;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "Pid:\t%d", &nr) == 1)
			break;
	fclose(f);
	return nr;
}

/* It is a pidfd like any other. There just is no task yet. */
TEST_F(cell, empty_pidfd)
{
	struct pidfd_info_v0 info = {};
	struct stat st, st_other;
	struct pollfd pfd;
	int pidfd, other;
	siginfo_t si;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);

	pidfd = prepare(self->c.cfd, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);

	/* Nothing exists, and nothing has happened to the cell. */
	EXPECT_EQ(cg_populated(self->c.cg), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_SEALED);

	/* Whatever it is passed to finds no task. */
	EXPECT_EQ(syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0), -1);
	EXPECT_EQ(errno, ESRCH);
	EXPECT_EQ(syscall(SYS_pidfd_getfd, pidfd, 0, 0), -1);
	EXPECT_EQ(errno, ESRCH);
	EXPECT_EQ(ioctl(pidfd, PIDFD_GET_INFO_V0, &info), -1);
	EXPECT_EQ(errno, ESRCH);
	/* Nor the record of an exit: nothing has exited. */
	info.mask = PIDFD_INFO_EXIT_V0;
	EXPECT_EQ(ioctl(pidfd, PIDFD_GET_INFO_V0, &info), -1);
	EXPECT_EQ(errno, ESRCH);
	info.mask = 0;
	/* -1 is for a task that is gone. */
	EXPECT_EQ(pidfd_fdinfo_pid(pidfd), 0);
	EXPECT_EQ(setns(pidfd, CLONE_NEWNET), -1);
	EXPECT_EQ(errno, ESRCH);
	EXPECT_EQ(waitid(P_PIDFD, pidfd, &si, WEXITED | WNOHANG), -1);
	EXPECT_EQ(errno, ECHILD);
	/* No task yet is not the same as no task any more. */
	pfd = (struct pollfd){ .fd = pidfd, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 100), 0);
	ASSERT_EQ(fstat(pidfd, &st), 0);

	/* What may not be given. */
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, self->c.cfd), -1);
	EXPECT_EQ(errno, EPERM);
	other = open("/proc/self/ns/net", O_RDONLY);
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, other), -1);
	EXPECT_EQ(errno, EPERM);
	close(other);
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, pidfd), -1);
	EXPECT_EQ(errno, EPERM);
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "nonsense", NULL, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_SET_BINARY, "argv", "unterminated", 12), -1);
	EXPECT_EQ(errno, EINVAL);
	/* An id the cell does not have. */
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_SET_BINARY, "cred",
				  &(struct pidfd_cred){ .uid = 70000 },
				  sizeof(struct pidfd_cred)), -1);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EBUSY);
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_SET_STRING, "exec", "/x", 0), -1);
	EXPECT_EQ(errno, EBUSY);

	/* Now there is one: in the cell, as the cell's root. */
	pid = pidfd_nr(pidfd);
	ASSERT_GT(pid, 0);
	EXPECT_GE(host_uid(pid), (long)CELL_WINDOW_FIRST);
	EXPECT_EQ(cg_populated(self->c.cg), 1);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_RUNNING);
	EXPECT_EQ(syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0), 0);
	EXPECT_EQ(poll(&pfd, 1, 100), 0);
	EXPECT_EQ(pidfd_fdinfo_pid(pidfd), pid);

	/* Another pidfd on it is the same inode, which did not change either. */
	other = sys_pidfd_open(pid, 0);
	ASSERT_GE(other, 0);
	ASSERT_EQ(fstat(other, &st_other), 0);
	EXPECT_EQ(st.st_ino, st_other.st_ino);
	ASSERT_EQ(fstat(pidfd, &st_other), 0);
	EXPECT_EQ(st.st_ino, st_other.st_ino);
	/* But only the file pidfd_open() returned for PIDFD_EMPTY configures. */
	EXPECT_EQ(pidfd_configure(other, PIDFD_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EPERM);
	close(other);
	close(pidfd);

	/* A second one, into the running cell. */
	pidfd = spawn(self->c.cfd, NULL, "second", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	pfd.fd = pidfd;
	EXPECT_EQ(poll(&pfd, 1, 10000), 1);
	info.mask = PIDFD_INFO_EXIT_V0;
	ASSERT_EQ(ioctl(pidfd, PIDFD_GET_INFO_V0, &info), 0);
	EXPECT_EQ(info.exit_code, 0);
	close(pidfd);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_RUNNING);
}

/*
 * An empty pidfd reserves nothing in the cell. Whichever is started first is
 * the init, and one that is left empty keeps the cell from nothing.
 */
TEST_F(cell, empty_pidfd_reserves_nothing)
{
	struct pollfd pfd;
	int a, b, c;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);

	/* "basic" insists on being pid 1, "second" on not being it. */
	a = prepare(self->c.cfd, "second", NULL, NULL);
	b = prepare(self->c.cfd, "pause", NULL, NULL);
	c = prepare(self->c.cfd, "pause", NULL, NULL);
	ASSERT_GE(a, 0);
	ASSERT_GE(b, 0);
	ASSERT_GE(c, 0);
	ASSERT_EQ(pidfd_configure(b, PIDFD_CMD_START, NULL, NULL, 0), 0);
	ASSERT_EQ(pidfd_configure(a, PIDFD_CMD_START, NULL, NULL, 0), 0);
	pfd = (struct pollfd){ .fd = a, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 10000), 1);
	do {
		struct pidfd_info_v0 info = { .mask = PIDFD_INFO_EXIT_V0 };

		ASSERT_EQ(ioctl(a, PIDFD_GET_INFO_V0, &info), 0);
		EXPECT_EQ(info.exit_code, 0);
	} while (0);

	/* The cell dies with @c still there, and then nothing comes of @c. */
	ASSERT_EQ(cell_kill(self->c.cfd, 0), 0);
	EXPECT_EQ(cell_wait_dead(self->c.cfd), SIGKILL);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	EXPECT_EQ(pidfd_configure(c, PIDFD_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, ESRCH);
	close(a);
	close(b);
	close(c);
}

/*
 * A start that fails before there is a task. The pidfd then says that there is
 * none and never will be, every way it can be asked, and the cell is as it was.
 */
TEST_F(cell, start_fails_without_a_task)
{
	struct pidfd_info_v0 info = { .mask = PIDFD_INFO_EXIT_V0 };
	struct pollfd pfd;
	char path[192];
	int pidfd;

	write_file(CGROOT "/cgroup.subtree_control", "+pids");
	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	snprintf(path, sizeof(path), "%s/pids.max", self->c.cg);
	if (write_file(path, "0")) {
		TH_LOG("no pids controller, skipped");
		return;
	}

	pidfd = prepare(self->c.cfd, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EAGAIN);
	EXPECT_EQ(cg_populated(self->c.cg), 0);

	/* It can be tried only once. */
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EBUSY);
	pfd = (struct pollfd){ .fd = pidfd, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 1000), 1);
	EXPECT_EQ(ioctl(pidfd, PIDFD_GET_INFO_V0, &info), -1);
	EXPECT_EQ(errno, ESRCH);
	EXPECT_EQ(pidfd_fdinfo_pid(pidfd), -1);
	EXPECT_EQ(syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0), -1);
	EXPECT_EQ(errno, ESRCH);
	close(pidfd);

	/* Nothing ever ran, so the next one is the init of the cell. */
	EXPECT_EQ(cell_state(self->c.cfd), CELL_SEALED);
	ASSERT_EQ(write_file(path, "max"), 0);
	pidfd = spawn(self->c.cfd, NULL, "basic", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	EXPECT_EQ(cell_wait_dead(self->c.cfd), 0);
	close(pidfd);
}

/* The pidfd may be kept for long. What was configured is not kept with it. */
TEST_F(cell, pidfd_keeps_no_file)
{
	int p[2], pidfd;
	char c;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	ASSERT_EQ(pipe2(p, O_CLOEXEC), 0);
	pidfd = prepare(self->c.cfd, "exit", "0", NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, p[1]), 0);
	close(p[1]);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);
	EXPECT_EQ(cell_wait_dead(self->c.cfd), 0);
	/* The last writer is gone, though the pidfd is not. */
	ASSERT_EQ(fcntl(p[0], F_SETFL, O_NONBLOCK), 0);
	EXPECT_EQ(read(p[0], &c, 1), 0);
	close(p[0]);
	close(pidfd);
}

TEST_F(cell, exec_failure_is_reported)
{
	int pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = prepare(self->c.cfd, "basic", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_STRING, "exec", "/no/such/file", 0), 0);
	EXPECT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, ENOENT);
	/* That was the cell's init. */
	EXPECT_EQ(cell_wait(self->c.cfd), SIGKILL);
	close(pidfd);
}

TEST_F(cell, cred)
{
	int pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = prepare(self->c.cfd, "uid", "33", "44");
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_BINARY, "cred",
				 &(struct pidfd_cred){ .uid = 33, .gid = 44 },
				 sizeof(struct pidfd_cred)), 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);
	EXPECT_EQ(cell_wait(self->c.cfd), 0);
	close(pidfd);
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

	pidfd = prepare(self->c.cfd, "exit", "0", NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, sp[1]), 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_STRING, "exec", "/no-such-file", 0), 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), -1);
	ASSERT_EQ(errno, ENOENT);
	close(pidfd);

	EXPECT_EQ(send_one_fd(sp[0], sp[0]), 0);
	close(sp[0]);
	close(sp[1]);
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

/* The exec of an embryo is no system call. This is how a filter prevents it. */
TEST_F(cell, seccomp_can_deny_a_start)
{
	int status;
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		if (seccomp_deny(__NR_pidfd_configure))
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

TEST_HARNESS_MAIN
