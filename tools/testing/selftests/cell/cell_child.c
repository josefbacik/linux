// SPDX-License-Identifier: GPL-2.0
/*
 * What runs inside a cell for cell_test. Statically linked: the tree of the
 * cell holds this file and nothing else.
 *
 * Usage: cell_child <check>. Complains on stderr, exits 0 if all is well.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <linux/capability.h>

#include "cell_util.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

extern char **environ;
static int failures;

#define CHECK(cond, fmt, ...) do {						\
	if (!(cond)) {								\
		fprintf(stderr, "cell_child: %s:%d: " fmt "\n", __func__,	\
			__LINE__, ##__VA_ARGS__);				\
		failures++;							\
	}									\
} while (0)

#define CHECK_ERRNO(call, err) do {						\
	errno = 0;								\
	long __r = (long)(call);						\
	CHECK(__r == -1 && errno == (err), "%s: returned %ld, errno %d, wanted %d", \
	      #call, __r, errno, (err));					\
} while (0)

/* Nothing but what was given. */
static void check_basic(void)
{
	struct cell_info info = { .mask = CELL_INFO_ID };
	struct cell_clone_args ca = {
		.flags = CLONE_PIDFD | CLONE_EMBRYO | CLONE_INTO_CELL | CLONE_AUTOREAP,
	};
	char buf[256];
	int fd, pidfd, nr = 0;

	CHECK(getpid() == 1, "pid %d", getpid());
	CHECK(getppid() == 0, "ppid %d", getppid());
	CHECK(getuid() == 0 && geteuid() == 0, "uid %d euid %d", getuid(), geteuid());
	CHECK(getgid() == 0 && getegid() == 0, "gid %d egid %d", getgid(), getegid());
	CHECK(getgroups(0, NULL) == 0, "%d groups", getgroups(0, NULL));
	CHECK(getsid(0) == 1, "sid %d", getsid(0));
	CHECK(getpgrp() == 1, "pgrp %d", getpgrp());
	CHECK(getcwd(buf, sizeof(buf)) && !strcmp(buf, "/"), "cwd %s", buf);
	CHECK(!gethostname(buf, sizeof(buf)) && !strcmp(buf, "celltest"),
	      "hostname %s", buf);
	CHECK(umask(0) == 022, "umask");
	CHECK(open("/dev/tty", O_RDWR) == -1, "has a controlling terminal");

	for (fd = 0; fd < 1024; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			nr++;
	CHECK(nr == 3, "%d open files", nr);

	CHECK(environ[0] && !strcmp(environ[0], "CELL=yes") && !environ[1],
	      "environment");

	CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "no_new_privs is off");
	CHECK(prctl(PR_CAPBSET_READ, CAP_SETFCAP, 0, 0, 0) == 0,
	      "CAP_SETFCAP in the bounding set");
	CHECK(prctl(PR_CAPBSET_READ, CAP_CHOWN, 0, 0, 0) == 1,
	      "CAP_CHOWN not in the bounding set");

	CHECK(!cell_info(CELL_SELF, &info, sizeof(info), 0) && info.id != 0,
	      "own cell id %llu", (unsigned long long)info.id);

	/* The "spawn" slot is empty, whatever the file descriptor is. */
	CHECK_ERRNO(cell_create(CELL_SELF, 0), EPERM);
	ca.pidfd = (uintptr_t)&pidfd;
	for (ca.cell = 0; ca.cell < 8; ca.cell++)
		CHECK_ERRNO(syscall(SYS_clone3, &ca, sizeof(ca)), EPERM);
}

/* A task has no say in its namespaces. */
static void check_membership(void)
{
	static const int flags[] = {
		CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNET,
		CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP, 0x80 /* NEWTIME */,
	};
	static const char * const ns[] = {
		"user", "mnt", "pid", "net", "ipc", "uts", "cgroup", "time",
	};
	char path[64];
	unsigned int i;
	int fd;

	for (i = 0; i < ARRAY_SIZE(flags); i++)
		CHECK_ERRNO(unshare(flags[i]), EPERM);

	for (i = 0; i < ARRAY_SIZE(ns); i++) {
		snprintf(path, sizeof(path), "/proc/self/ns/%s", ns[i]);
		fd = open(path, O_RDONLY);
		CHECK(fd >= 0, "open %s: %d", path, errno);
		if (fd < 0)
			continue;
		CHECK_ERRNO(setns(fd, 0), EPERM);
		close(fd);
	}

	CHECK_ERRNO(syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0), EPERM);
	CHECK_ERRNO(syscall(SYS_clone, CLONE_NEWNET | SIGCHLD, 0, 0, 0, 0), EPERM);
	CHECK_ERRNO(syscall(SYS_open_tree, AT_FDCWD, "/", 2 /* OPEN_TREE_NAMESPACE */),
		    EPERM);
	CHECK_ERRNO(mount("none", "/tmp", "tmpfs", 0, NULL), EPERM);
	CHECK_ERRNO(umount2("/proc", MNT_DETACH), EPERM);
}

/* Nothing a cell writes imparts privilege. */
static void check_setid(void)
{
	/* VFS_CAP_REVISION_2, cap_net_raw permitted and effective. */
	static const unsigned char cap[20] = {
		0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00,
	};
	struct stat st;
	int fd;

	fd = open("/tmp/a", O_CREAT | O_WRONLY, 06755);
	CHECK(fd >= 0, "create: %d", errno);
	CHECK(!fstat(fd, &st) && !(st.st_mode & (S_ISUID | S_ISGID)),
	      "created with mode %o", st.st_mode);
	CHECK(st.st_uid == 0 && st.st_gid == 0, "owned by %d:%d", st.st_uid, st.st_gid);

	CHECK(!fchmod(fd, 06755), "fchmod: %d", errno);
	CHECK(!fstat(fd, &st) && (st.st_mode & 07777) == 0755,
	      "chmod gave mode %o", st.st_mode);
	CHECK(!chmod("/tmp/a", 04711), "chmod: %d", errno);
	CHECK(!stat("/tmp/a", &st) && (st.st_mode & 07777) == 0711,
	      "chmod gave mode %o", st.st_mode);

	CHECK_ERRNO(fsetxattr(fd, "security.capability", cap, sizeof(cap), 0), EPERM);
	close(fd);

	CHECK(!mknod("/tmp/f", S_IFIFO | 06644, 0), "mknod: %d", errno);
	CHECK(!stat("/tmp/f", &st) && !(st.st_mode & (S_ISUID | S_ISGID)),
	      "mknod gave mode %o", st.st_mode);

	/*
	 * A set-uid file that came with the tree. A store through a shared
	 * mapping would leave the bits alone, so being able to write is enough
	 * to lose them.
	 */
	CHECK(!stat("/su", &st) && (st.st_mode & 07777) == 06755, "mode %o", st.st_mode);
	fd = open("/su", O_RDONLY);
	CHECK(fd >= 0 && !fstat(fd, &st) && (st.st_mode & 07777) == 06755,
	      "reading cost the bits: %o", st.st_mode);
	close(fd);
	fd = open("/su", O_RDWR);
	CHECK(fd >= 0 && !fstat(fd, &st) && (st.st_mode & 07777) == 0755,
	      "still mode %o when open for writing", st.st_mode);
	close(fd);

	/* On a directory setgid is about inheritance, not privilege. */
	CHECK(!mkdir("/tmp/d", 0755) && !chmod("/tmp/d", 02755), "mkdir: %d", errno);
	CHECK(!stat("/tmp/d", &st) && (st.st_mode & S_ISGID), "mode %o", st.st_mode);

	/* Ids work as ever otherwise. */
	CHECK(!chown("/tmp/a", 33, 33), "chown: %d", errno);
	CHECK(!stat("/tmp/a", &st) && st.st_uid == 33 && st.st_gid == 33,
	      "owned by %d:%d", st.st_uid, st.st_gid);
}

static int send_fd(int sock, int fd)
{
	char data = 'x', ctl[CMSG_SPACE(sizeof(int))] = {};
	struct iovec iov = { .iov_base = &data, .iov_len = 1 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = ctl, .msg_controllen = sizeof(ctl),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	return sendmsg(sock, &msg, 0);
}

static void check_peer_queries(int sock)
{
	struct ucred uc;
	socklen_t len;
	gid_t groups[8];
	int pidfd;

	len = sizeof(uc);
	CHECK_ERRNO(getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &uc, &len), ENODATA);
	len = sizeof(groups);
	CHECK_ERRNO(getsockopt(sock, SOL_SOCKET, SO_PEERGROUPS, groups, &len), ENODATA);
	len = sizeof(pidfd);
	CHECK_ERRNO(getsockopt(sock, SOL_SOCKET, 77 /* SO_PEERPIDFD */, &pidfd, &len),
		    ENODATA);
}

/*
 * Between cells a socket carries bytes. fd 3 is one end of a socketpair the
 * host made, /tmp/sock a listener of the host's.
 */
static void check_unix(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = "/tmp/sock" };
	char ctl[256], c;
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = ctl, .msg_controllen = sizeof(ctl),
	};
	int one = 1, sock, sv[2];
	struct ucred uc;
	socklen_t len;

	/*
	 * The host queued a file on the socket while both ends were still its
	 * own. Nobody could have refused that. It must not arrive.
	 */
	CHECK(recvmsg(3, &msg, MSG_PEEK) == 1 && c == 'q', "peek: %d", errno);
	CHECK(msg.msg_controllen == 0, "peeked %zu bytes of ancillary data",
	      (size_t)msg.msg_controllen);
	msg.msg_controllen = sizeof(ctl);
	CHECK(recvmsg(3, &msg, 0) == 1 && c == 'q', "recvmsg: %d", errno);
	CHECK(msg.msg_controllen == 0, "got %zu bytes of ancillary data",
	      (size_t)msg.msg_controllen);
	CHECK(fcntl(4, F_GETFD) == -1, "a file arrived");
	msg.msg_controllen = sizeof(ctl);

	check_peer_queries(3);
	CHECK_ERRNO(send_fd(3, 0), EPERM);
	CHECK(write(3, "a", 1) == 1, "plain bytes: %d", errno);

	/* The host sends a byte, with SO_PASSCRED on at this end. */
	CHECK(!setsockopt(3, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)), "passcred");
	CHECK(write(3, "b", 1) == 1, "plain bytes: %d", errno);
	CHECK(recvmsg(3, &msg, 0) == 1 && c == 'h', "recvmsg: %d", errno);
	CHECK(msg.msg_controllen == 0, "got %zu bytes of ancillary data",
	      (size_t)msg.msg_controllen);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(!connect(sock, (struct sockaddr *)&addr, sizeof(addr)), "connect: %d", errno);
	check_peer_queries(sock);
	CHECK_ERRNO(send_fd(sock, 0), EPERM);
	CHECK(write(sock, "c", 1) == 1, "plain bytes: %d", errno);
	close(sock);

	/* Within the cell everything is as it always was. */
	CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv), "socketpair");
	len = sizeof(uc);
	CHECK(!getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &uc, &len) &&
	      uc.pid == getpid() && uc.uid == 0, "SO_PEERCRED at home: %d", errno);
	CHECK(send_fd(sv[0], 0) == 1, "SCM_RIGHTS at home: %d", errno);
	msg.msg_controllen = sizeof(ctl);
	CHECK(recvmsg(sv[1], &msg, 0) == 1 && msg.msg_controllen >= CMSG_LEN(sizeof(int)),
	      "no fd arrived at home");
}

/* fd 3 is a directory of a filesystem of the host that is not idmapped. */
static void check_dirfd(void)
{
	CHECK_ERRNO(openat(3, "x", O_CREAT | O_WRONLY, 0644), EOVERFLOW);
	CHECK_ERRNO(mkdirat(3, "d", 0755), EOVERFLOW);
	CHECK_ERRNO(fchownat(3, "world", 0, 0, 0), EOVERFLOW);
}

/* /data is a real filesystem, with a set-uid file that came with it. */
static void check_data(const char *create)
{
	struct stat st;
	int fd;

	fd = open("/data/su", O_RDWR);
	CHECK(fd >= 0, "open: %d", errno);
	CHECK(!fstat(fd, &st) && !(st.st_mode & (S_ISUID | S_ISGID)),
	      "still mode %o when open for writing", st.st_mode);
	close(fd);

	if (!create)
		return;
	/* With ->atomic_open() this opens under the lock of the directory. */
	fd = open("/data/new", O_CREAT | O_EXCL | O_RDWR, 06755);
	CHECK(fd >= 0, "create: %d", errno);
	CHECK(!fstat(fd, &st) && !(st.st_mode & (S_ISUID | S_ISGID)),
	      "created with mode %o", st.st_mode);
	CHECK(write(fd, "x", 1) == 1, "write: %d", errno);
	close(fd);
	CHECK(!unlink("/data/new"), "unlink: %d", errno);
}

/*
 * fd 3 is /dev/vhost-net. In its kthread mode vhost puts a kernel thread into
 * the cgroups of the owner. A kill could not take that with it.
 */
static void check_vhost(void)
{
	unsigned char mode = 0;		/* VHOST_FORK_OWNER_KTHREAD */

	CHECK(!ioctl(3, _IOW(0xAF, 0x84, unsigned char), &mode),
	      "VHOST_SET_FORK_FROM_OWNER: %d", errno);
	/* vhost makes ENOMEM of whatever went wrong with its worker. */
	CHECK(ioctl(3, _IO(0xAF, 0x01) /* VHOST_SET_OWNER */) == -1,
	      "VHOST_SET_OWNER worked");
}

/* The spawner ignores, handles and blocks signals. None of that is ours. */
static void check_signals(void)
{
	struct sigaction sa;
	sigset_t set;
	int sig;

	for (sig = 1; sig < _NSIG; sig++) {
		/* The C library keeps a few to itself. */
		if (sigaction(sig, NULL, &sa))
			continue;
		CHECK(sa.sa_handler == SIG_DFL, "signal %d is not at its default", sig);
	}
	CHECK(!sigprocmask(SIG_BLOCK, NULL, &set), "sigprocmask: %d", errno);
	for (sig = 1; sig < _NSIG; sig++)
		CHECK(sigismember(&set, sig) != 1, "signal %d is blocked", sig);
	CHECK(!sigpending(&set), "sigpending: %d", errno);
	for (sig = 1; sig < _NSIG; sig++)
		CHECK(sigismember(&set, sig) != 1, "signal %d is pending", sig);
}

/* The spawner has a filter that fails getrusage() with EACCES. */
static void check_seccomp(void)
{
	struct rusage ru;

	CHECK_ERRNO(getrusage(RUSAGE_SELF, &ru), EACCES);
}

static void on_usr1(int sig)
{
	_exit(0);
}

/*
 * An init only gets the signals it has a handler for, so without one nobody
 * could tell a signal that was refused from one that was dropped.
 */
static void wait_for_usr1(void)
{
	signal(SIGUSR1, on_usr1);
	/* Whoever wants to know that we are ready put a pipe there. */
	if (write(3, "x", 1) < 0)
		;
	for (;;)
		pause();
}

/* Spawned into a running cell: the parent is somebody outside. */
static void check_second(void)
{
	CHECK(getpid() != 1 && getppid() == 0, "pid %d ppid %d", getpid(), getppid());
	CHECK_ERRNO(ptrace(PTRACE_TRACEME, 0, 0, 0), EPERM);
}

static void check_oneid(const char *uid)
{
	struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3 };
	struct __user_cap_data_struct data[2];

	CHECK((int)getuid() == atoi(uid), "uid %d", getuid());
	CHECK(!syscall(SYS_capget, &hdr, data) && !data[0].permitted &&
	      !data[1].permitted && !data[0].effective, "has capabilities");
	CHECK_ERRNO(setuid(getuid() + 1), EINVAL);
	CHECK_ERRNO(setgroups(0, NULL), EPERM);
	/* The groups of whoever made the cell, denials and all. */
	CHECK(getgroups(0, NULL) == 2, "%d groups", getgroups(0, NULL));

	/* The parent has the very same uid. It is not in this cell. */
	CHECK(syscall(SYS_keyctl, 1 /* JOIN_SESSION_KEYRING */, NULL) > 0,
	      "join session keyring: %d", errno);
	CHECK_ERRNO(syscall(SYS_keyctl, 18 /* SESSION_TO_PARENT */), EPERM);
	CHECK_ERRNO(ptrace(PTRACE_TRACEME, 0, 0, 0), EPERM);
}

int main(int argc, char **argv)
{
	const char *what = argc > 1 ? argv[1] : "";

	if (!strcmp(what, "basic"))
		check_basic();
	else if (!strcmp(what, "membership"))
		check_membership();
	else if (!strcmp(what, "setid"))
		check_setid();
	else if (!strcmp(what, "unix"))
		check_unix();
	else if (!strcmp(what, "dirfd"))
		check_dirfd();
	else if (!strcmp(what, "oneid"))
		check_oneid(argv[2]);
	else if (!strcmp(what, "pause"))
		for (;;)
			pause();
	else if (!strcmp(what, "usr1"))
		wait_for_usr1();
	else if (!strcmp(what, "seccomp"))
		check_seccomp();
	else if (!strcmp(what, "signals"))
		check_signals();
	else if (!strcmp(what, "forkbomb"))
		for (;;)
			fork();
	else if (!strcmp(what, "exit"))
		return atoi(argv[2]);
	else if (!strcmp(what, "vhost"))
		check_vhost();
	else if (!strcmp(what, "data"))
		check_data(argv[2]);
	else if (!strcmp(what, "second"))
		check_second();
	else if (!strcmp(what, "uid"))
		return ((int)getuid() == atoi(argv[2]) && (int)getgid() == atoi(argv[3])) ? 0 : 1;
	else
		return 99;

	return failures ? 1 : 0;
}
