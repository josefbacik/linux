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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>

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
	char buf[256];
	int fd, nr = 0;

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
	for (fd = -1; fd < 8; fd++)
		CHECK_ERRNO(pidfd_open_empty(fd, 0), EPERM);
	CHECK_ERRNO(pidfd_open_empty(-EBADF, 0), EPERM);
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

static int write_str(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY), ret;

	if (fd < 0)
		return -1;
	ret = write(fd, val, strlen(val)) < 0 ? -1 : 0;
	close(fd);
	return ret;
}

/*
 * All of cgroupfs is at /data, and /data/open and its files are there for
 * anybody to write. It is not within the budget.
 */
static void check_outside_the_budget(void)
{
	CHECK_ERRNO(write_str("/data/open/cgroup.subtree_control", "+pids"), EPERM);
	CHECK_ERRNO(write_str("/data/open/cgroup.procs", "0"), EPERM);
	CHECK_ERRNO(write_str("/data/open/pids.max", "1"), EPERM);
	CHECK_ERRNO(rmdir("/data/open/empty"), EPERM);
	CHECK_ERRNO(chmod("/data/open", 0700), EPERM);
	/* These may not get that far: the id of the caller cannot be stored here. */
	CHECK(mkdir("/data/open/mine", 0755) && (errno == EPERM || errno == EOVERFLOW),
	      "mkdir: %d", errno);
	CHECK(rename("/data/open/empty", "/data/open/other") &&
	      (errno == EPERM || errno == EOVERFLOW), "rename: %d", errno);
	CHECK(chown("/data/open", 0, 0) && (errno == EPERM || errno == EOVERFLOW),
	      "chown: %d", errno);
	/* Neither of these asks cgroup anything. */
	CHECK_ERRNO(setxattr("/data/open", "user.cell", "x", 1, 0), EPERM);
	CHECK_ERRNO(setxattr("/data/open", "user.host", "x", 1, 0), EPERM);
	CHECK_ERRNO(removexattr("/data/open", "user.host"), EPERM);
	CHECK_ERRNO(utimensat(AT_FDCWD, "/data/open", NULL, 0), EPERM);
	CHECK_ERRNO(open("/data/open/cgroup.procs", O_WRONLY), EPERM);
	CHECK(open("/data/open/cgroup.procs", O_RDONLY) >= 0, "open to read: %d", errno);
}

/* A legacy hierarchy has no budget on it, and it can rename. */
static void check_legacy_hierarchy(void)
{
	CHECK_ERRNO(rename("/data/open/empty", "/data/open/other"), EPERM);
	CHECK_ERRNO(rmdir("/data/open/empty"), EPERM);
	CHECK_ERRNO(write_str("/data/open/cgroup.procs", "0"), EPERM);
	CHECK_ERRNO(write_str("/data/open/notify_on_release", "1"), EPERM);
	CHECK_ERRNO(setxattr("/data/open", "user.cell", "x", 1, 0), EPERM);
	CHECK(mkdir("/data/open/mine", 0755) && (errno == EPERM || errno == EOVERFLOW),
	      "mkdir: %d", errno);
}

/*
 * A cell of one id runs on the id of its maker, so it owns what its maker owns.
 * File descriptor 3 is on a cgroup of the maker's that is not within the budget.
 */
static void check_outside_but_its_own(void)
{
	struct stat st;

	CHECK(!fstat(3, &st) && st.st_uid == getuid(), "owner %u", st.st_uid);
	CHECK_ERRNO(fchmod(3, 0700), EPERM);
	CHECK_ERRNO(fchown(3, -1, getgid()), EPERM);
	CHECK_ERRNO(futimens(3, NULL), EPERM);
	CHECK_ERRNO(fsetxattr(3, "user.cell", "x", 1, 0), EPERM);
	CHECK_ERRNO(fremovexattr(3, "user.host"), EPERM);
	CHECK_ERRNO(mkdirat(3, "mine", 0755), EPERM);
	CHECK_ERRNO(unlinkat(3, "empty", AT_REMOVEDIR), EPERM);
	CHECK_ERRNO(openat(3, "cgroup.procs", O_WRONLY), EPERM);
	CHECK_ERRNO(fchmodat(3, "cgroup.procs", 0666, 0), EPERM);
	/* File descriptor 4 was opened for writing by the maker. */
	CHECK_ERRNO(write(4, "5", 1), EPERM);
	/* File descriptor 5, if there is one, is the same on a legacy hierarchy. */
	if (fstat(5, &st))
		return;
	CHECK(st.st_uid == getuid(), "owner %u", st.st_uid);
	CHECK_ERRNO(renameat(5, "empty", 5, "other"), EPERM);
	CHECK_ERRNO(mkdirat(5, "mine", 0755), EPERM);
	CHECK_ERRNO(unlinkat(5, "empty", AT_REMOVEDIR), EPERM);
	CHECK_ERRNO(fchmod(5, 0700), EPERM);
	CHECK_ERRNO(fsetxattr(5, "user.cell", "x", 1, 0), EPERM);
}

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD	77
#endif

static int race_sock = -1, race_stop, race_hits;

static void *peer_race_ask(void *arg)
{
	while (!__atomic_load_n(&race_stop, __ATOMIC_RELAXED)) {
		int s = __atomic_load_n(&race_sock, __ATOMIC_RELAXED), fd = -1;
		socklen_t len = sizeof(int);

		if (s >= 0 && !getsockopt(s, SOL_SOCKET, SO_PEERPIDFD, &fd, &len)) {
			__atomic_fetch_add(&race_hits, 1, __ATOMIC_RELAXED);
			close(fd);
		}
	}
	return NULL;
}

/*
 * Who the peer is must be checked and read in one go. One thread connects a
 * fresh socket to a listener of the host's, over and over, while another asks
 * each of them for a pidfd on its peer. There is no moment at which it gets one.
 */
static void check_peer_race(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = "/tmp/sock" };
	time_t end = time(NULL) + 8;
	pthread_t ask[2];
	int i, s, connected = 0;

	for (i = 0; i < 2; i++)
		CHECK(!pthread_create(&ask[i], NULL, peer_race_ask, NULL), "thread");
	while (time(NULL) < end) {
		s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (s < 0)
			break;
		__atomic_store_n(&race_sock, s, __ATOMIC_RELAXED);
		if (!connect(s, (struct sockaddr *)&addr, sizeof(addr)))
			connected++;
		__atomic_store_n(&race_sock, -1, __ATOMIC_RELAXED);
		close(s);
	}
	__atomic_store_n(&race_stop, 1, __ATOMIC_RELAXED);
	for (i = 0; i < 2; i++)
		pthread_join(ask[i], NULL);
	CHECK(connected > 100, "only %d connected", connected);
	CHECK(!race_hits, "%d pidfds on a task of the host in %d connects",
	      race_hits, connected);
}

static const struct sockaddr_in pod_addr = {
	.sin_family = AF_INET,
	.sin_port = __builtin_bswap16(7777),
	.sin_addr = { __builtin_bswap32(INADDR_LOOPBACK) },
};

/* One container of a pod: leaves a file on the volume and serves on localhost. */
static void pod_serve(void)
{
	int one = 1, fd, lsock, conn;
	char c = 0;

	fd = open("/data/from-a", O_CREAT | O_WRONLY, 0600);
	CHECK(fd >= 0, "create on the volume: %d", errno);
	close(fd);
	lsock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	CHECK(lsock >= 0, "socket: %d", errno);
	setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	CHECK(!bind(lsock, (const struct sockaddr *)&pod_addr, sizeof(pod_addr)),
	      "bind: %d", errno);
	CHECK(!listen(lsock, 1), "listen: %d", errno);
	/* Ready. */
	CHECK(write(3, "r", 1) == 1, "ready: %d", errno);
	conn = accept(lsock, NULL, NULL);
	CHECK(conn >= 0, "accept: %d", errno);
	CHECK(read(conn, &c, 1) == 1 && c == 'p', "read '%c': %d", c, errno);
	CHECK(write(conn, "q", 1) == 1, "write: %d", errno);
}

/* Another one: finds the file, as its own root's, and talks to the first. */
static void pod_connect(void)
{
	struct stat st;
	char c = 0;
	int sock;

	CHECK(!stat("/data/from-a", &st), "stat on the volume: %d", errno);
	CHECK(st.st_uid == 0 && st.st_gid == 0, "owner %u:%u", st.st_uid, st.st_gid);
	sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	CHECK(sock >= 0, "socket: %d", errno);
	CHECK(!connect(sock, (const struct sockaddr *)&pod_addr, sizeof(pod_addr)),
	      "connect: %d", errno);
	CHECK(write(sock, "p", 1) == 1, "write: %d", errno);
	CHECK(read(sock, &c, 1) == 1 && c == 'q', "read '%c': %d", c, errno);
}

/* The network. */

static bool has_cap(int cap)
{
	struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3 };
	struct __user_cap_data_struct data[2] = {};

	return !syscall(SYS_capget, &hdr, data) && (data[cap / 32].effective & (1U << (cap % 32)));
}

/* An empty request of @type. -EPERM comes before any of it is looked at. */
static int rtnl_poke(int type)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr h;
		char body[64];
	} req = { .h = { sizeof(req), type, NLM_F_REQUEST | NLM_F_ACK } };
	char buf[1024];
	struct nlmsghdr *h = (void *)buf;
	int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE), n;

	if (s < 0 || sendto(s, &req, sizeof(req), 0, (void *)&sa, sizeof(sa)) < 0)
		return -errno;
	n = recv(s, buf, sizeof(buf), 0);
	close(s);
	if (n < (int)sizeof(*h) || h->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;
	return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
}

/* Returns the flags of @dev as they were, or a negative error. */
static int dev_flags(const char *dev, int set, int clear)
{
	struct ifreq ifr = {};
	int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), was, r;

	strcpy(ifr.ifr_name, dev);
	r = ioctl(s, SIOCGIFFLAGS, &ifr);
	was = (unsigned short)ifr.ifr_flags;
	if (!r && (set || clear)) {
		ifr.ifr_flags = (was | set) & ~clear;
		r = ioctl(s, SIOCSIFFLAGS, &ifr);
	}
	r = r ? -errno : was;
	close(s);
	return r;
}

static int dev_set_addr(const char *dev, unsigned int ip)
{
	struct ifreq ifr = {};
	struct sockaddr_in *sin = (void *)&ifr.ifr_addr;
	int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), r;

	strcpy(ifr.ifr_name, dev);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = __builtin_bswap32(ip);
	r = ioctl(s, SIOCSIFADDR, &ifr) ? -errno : 0;
	close(s);
	return r;
}

static int try_bind(int port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = __builtin_bswap16(port) };
	int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), r;

	r = bind(s, (void *)&a, sizeof(a)) ? -errno : 0;
	close(s);
	return r;
}

static int try_connect(unsigned int ip, int port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = __builtin_bswap16(port),
				 .sin_addr = { __builtin_bswap32(ip) } };
	int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (connect(s, (void *)&a, sizeof(a))) {
		int err = errno;

		close(s);
		return -err;
	}
	return s;
}

/*
 * Whoever set the network up is who can change it. @own: it is the cell's own,
 * which is the control: these do tell.
 */
static void check_net_config(const char *dev, bool own)
{
	static const int types[] = {
		RTM_NEWLINK, RTM_DELLINK, RTM_SETLINK, RTM_NEWADDR, RTM_DELADDR, RTM_NEWROUTE,
		RTM_DELROUTE, RTM_NEWNEIGH, RTM_NEWRULE, RTM_NEWQDISC, RTM_NEWTFILTER,
		RTM_NEWNSID,
	};
	int one = 1, r, s;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(types); i++) {
		r = rtnl_poke(types[i]);
		CHECK(own ? r != -EPERM : r == -EPERM, "rtnetlink %d: %d", types[i], r);
	}
	r = dev_flags(dev, IFF_UP, 0);
	CHECK(own ? r >= 0 : r == -EPERM, "%s up: %d", dev, r);
	r = dev_flags(dev, 0, IFF_UP);
	CHECK(own ? r >= 0 : r == -EPERM, "%s down: %d", dev, r);
	r = dev_set_addr(dev, 0x0a0900fe);
	CHECK(own ? !r : r == -EPERM, "address on %s: %d", dev, r);
	s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	r = setsockopt(s, SOL_SOCKET, SO_MARK, &one, sizeof(one)) ? -errno : 0;
	CHECK(own ? !r : r == -EPERM, "SO_MARK: %d", r);
	close(s);
	s = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
	CHECK(own ? s >= 0 : (s == -1 && errno == EPERM), "raw socket: %d, %d", s, errno);
	s = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
	CHECK(own ? s >= 0 : (s == -1 && errno == EPERM), "packet socket: %d, %d", s, errno);
	r = write_str("/proc/sys/net/ipv4/ip_forward", "1") ? -errno : 0;
	CHECK(own ? !r : r == -EACCES, "net sysctl: %d", r);
	r = try_bind(80);
	CHECK(own ? !r : r == -EACCES, "port 80: %d", r);
}

/* Nobody has set it up: there is a loopback device that is down, and that is that. */
static void check_net_bare(void)
{
	struct if_nameindex *ni = if_nameindex();
	int r;

	CHECK(ni && ni[0].if_name && !strcmp(ni[0].if_name, "lo") && !ni[1].if_index,
	      "more than lo");
	r = dev_flags("lo", 0, 0);
	CHECK(r >= 0 && !(r & IFF_UP), "lo: %x", r);
	r = try_connect(INADDR_LOOPBACK, 7777);
	CHECK(r == -ENETUNREACH, "connect: %d", r);
	check_net_config("lo", false);
}

/*
 * The slot was left empty, so there is no network: no socket but a unix socket,
 * and nothing to be learned about a network through any socket. File descriptor
 * 3 is a socket of the host's that listens on its loopback device. What is handed
 * to the cell works.
 */
static void check_net_none(void)
{
	static const int families[] = {
		AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, AF_ALG, AF_VSOCK, AF_KEY, AF_XDP,
		AF_BLUETOOTH, AF_CAN, AF_TIPC,
	};
	static const unsigned long about_the_net[] = {
		SIOCGIFCONF, SIOCGIFFLAGS, SIOCSIFFLAGS, SIOCGIFADDR, SIOCSIFADDR, SIOCGIFINDEX,
		SIOCGIFNAME, SIOCGIFHWADDR, SIOCADDRT, SIOCDELRT, SIOCGARP, SIOCGIFBR,
		SIOCBRADDBR, SIOCGIFVLAN, SIOCDEVPRIVATE, SIOCGSKNS, 0x8B01 /* SIOCGIWNAME */,
	};
	struct sockaddr_un addr = { .sun_family = AF_UNIX, .sun_path = "\0cell-test" };
	int sp[2], socks[2], s, l, n, pending;
	unsigned int i, j;
	char c = 0;

	for (i = 0; i < ARRAY_SIZE(families); i++) {
		CHECK_ERRNO(socket(families[i], SOCK_DGRAM | SOCK_CLOEXEC, 0), EAFNOSUPPORT);
		CHECK_ERRNO(socket(families[i], SOCK_STREAM | SOCK_CLOEXEC, 0), EAFNOSUPPORT);
		CHECK_ERRNO(socket(families[i], SOCK_RAW | SOCK_CLOEXEC, 0), EAFNOSUPPORT);
		CHECK_ERRNO(socketpair(families[i], SOCK_STREAM, 0, sp), EAFNOSUPPORT);
	}
	CHECK(!if_nameindex(), "there are devices to be listed");

	/* Unix sockets are not the network. */
	CHECK(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp), "socketpair: %d", errno);
	l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	CHECK(l >= 0 && !bind(l, (void *)&addr, sizeof(sa_family_t) + 10) && !listen(l, 1),
	      "an abstract unix socket: %d", errno);
	s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	CHECK(!connect(s, (void *)&addr, sizeof(sa_family_t) + 10), "connect to it: %d", errno);

	/* What was handed over works, new sockets that come of it included. */
	n = accept4(3, NULL, NULL, SOCK_CLOEXEC);
	CHECK(n >= 0, "accept: %d", errno);
	CHECK(read(n, &c, 1) == 1 && c == 'h' && write(n, "c", 1) == 1,
	      "talk to the host: '%c', %d", c, errno);

	/* About the socket: fine. About the network it is in: there is none. */
	socks[0] = s;
	socks[1] = n;
	for (j = 0; j < ARRAY_SIZE(socks); j++) {
		CHECK(!ioctl(socks[j], FIONREAD, &pending), "FIONREAD on %u: %d", j, errno);
		CHECK(!ioctl(socks[j], SIOCGPGRP, &pending), "SIOCGPGRP on %u: %d", j, errno);
		/* In among those that are about devices, by its number. */
		if (j)
			CHECK(!ioctl(socks[j], SIOCOUTQNSD, &pending), "SIOCOUTQNSD: %d", errno);
		for (i = 0; i < ARRAY_SIZE(about_the_net); i++) {
			struct ifreq ifr = { .ifr_name = "lo" };

			errno = 0;
			CHECK(ioctl(socks[j], about_the_net[i], &ifr) == -1 && errno == ENODEV,
			      "ioctl %#lx on %u: %d", about_the_net[i], j, errno);
		}
	}
}

/* "new", and whoever built the cell has brought lo up before sealing it. */
static void check_net_lo(void)
{
	int r = dev_flags("lo", 0, 0);

	CHECK(r >= 0 && (r & IFF_UP), "lo: %x", r);
	r = try_connect(INADDR_LOOPBACK, 7777);
	CHECK(r == -ECONNREFUSED, "connect: %d", r);
	check_net_config("lo", false);
}

/*
 * One end of a veth pair, with an address. The host listens at the other end.
 * File descriptors 3 and 4 are for telling the host to add an address meanwhile.
 */
static void check_net_given(void)
{
	char c = 0;
	int s;

	s = try_connect(0x0a090001, 7777);
	CHECK(s >= 0, "connect to the host: %d", s);
	CHECK(write(s, "c", 1) == 1 && read(s, &c, 1) == 1 && c == 'h',
	      "talk to the host: '%c', %d", c, errno);
	close(s);
	CHECK(!try_bind(8080), "port 8080");

	CHECK(try_connect(0x0a090003, 9) == -ENETUNREACH ||
	      try_connect(0x0a090003, 9) == -EHOSTUNREACH, "the address is there already");
	CHECK(write(3, "a", 1) == 1 && read(4, &c, 1) == 1, "handshake: %d", errno);
	s = try_connect(0x0a090003, 9);
	CHECK(s == -ECONNREFUSED, "the address that was added from the outside: %d", s);

	check_net_config("vc0", false);
}

/* Low ports and ping are settings of the network namespace. */
static void check_net_settings(const char *when)
{
	struct sockaddr_in lo = { .sin_family = AF_INET,
				  .sin_addr = { __builtin_bswap32(INADDR_LOOPBACK) } };
	struct {
		unsigned char type, code;
		unsigned short sum, id, seq;
	} echo = { .type = 8 }, reply = { .type = 0xff };
	bool after = !strcmp(when, "after");
	int r, s;

	r = try_bind(80);
	CHECK(after ? !r : r == -EACCES, "port 80: %d", r);
	s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_ICMP);
	CHECK(after ? s >= 0 : (s == -1 && errno == EACCES), "ping socket: %d, %d", s, errno);
	if (s >= 0) {
		CHECK(sendto(s, &echo, sizeof(echo), 0, (void *)&lo, sizeof(lo)) == sizeof(echo),
		      "echo: %d", errno);
		CHECK(recv(s, &reply, sizeof(reply), 0) == sizeof(reply) && !reply.type,
		      "echo reply: type %d, %d", reply.type, errno);
		close(s);
	}
	/* They are not the cell's to change back. */
	CHECK_ERRNO(write_str("/proc/sys/net/ipv4/ip_unprivileged_port_start", "1024"), EACCES);
	CHECK_ERRNO(write_str("/proc/sys/net/ipv4/ping_group_range", "1 0"), EACCES);
}

/* Is there a network at all? */
static void check_net_at_all(const char *want)
{
	int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	if (!strcmp(want, "yes"))
		CHECK(s >= 0, "socket: %d", errno);
	else
		CHECK(s == -1 && errno == EAFNOSUPPORT, "socket: %d, %d", s, errno);
}

/* "own": asked for, and only then. */
static void check_net_own(void)
{
	CHECK(has_cap(CAP_NET_ADMIN), "no CAP_NET_ADMIN");
	check_net_config("lo", true);
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
	else if (!strcmp(what, "outside"))
		check_outside_the_budget();
	else if (!strcmp(what, "net-none"))
		check_net_none();
	else if (!strcmp(what, "net-at-all"))
		check_net_at_all(argv[2]);
	else if (!strcmp(what, "net-bare"))
		check_net_bare();
	else if (!strcmp(what, "net-lo"))
		check_net_lo();
	else if (!strcmp(what, "net-given"))
		check_net_given();
	else if (!strcmp(what, "net-settings"))
		check_net_settings(argv[2]);
	else if (!strcmp(what, "net-own"))
		check_net_own();
	else if (!strcmp(what, "legacy"))
		check_legacy_hierarchy();
	else if (!strcmp(what, "outside-own"))
		check_outside_but_its_own();
	else if (!strcmp(what, "peer-race"))
		check_peer_race();
	else if (!strcmp(what, "pod-serve"))
		pod_serve();
	else if (!strcmp(what, "pod-connect"))
		pod_connect();
	else if (!strcmp(what, "uid"))
		return ((int)getuid() == atoi(argv[2]) && (int)getgid() == atoi(argv[3])) ? 0 : 1;
	else
		return 99;

	return failures ? 1 : 0;
}
