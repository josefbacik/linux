// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for cells, ids: the window, the blocks, and that nothing a cell writes
 * imparts privilege.
 */
#include "cell_test.h"

/* Root does not get a cell on kuid 0, least of all by default. */
TEST_F(cell, no_cell_on_uid_0)
{
	EXPECT_EQ(cell_build(&self->c, &(struct build){ .ids = 1 }), 4);
	EXPECT_EQ(errno, EPERM);
	cell_cleanup(&self->c);
	EXPECT_EQ(cell_build(&self->c, &(struct build){ .ids = 0 }), 18);
	EXPECT_EQ(errno, EPERM);
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

/* There are only so many blocks, and no one user gets them all. */
TEST_F(cell, blocks_are_counted)
{
	unsigned int ids = 65536;
	int status;
	pid_t pid;

	ASSERT_EQ(write_file("/proc/sys/user/max_cell_id_blocks", "1"), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		int a, b;

		/*
		 * They are counted by user, and a block goes on counting until
		 * the user namespace it was lent to is freed, some time after
		 * the cell is dead. So as a user that never had one.
		 */
		if (setresgid(54321, 54321, 54321) || setresuid(54321, 54321, 54321))
			_exit(1);
		a = cell_create(CELL_SELF, 0);
		b = cell_create(CELL_SELF, 0);
		if (a < 0 || b < 0)
			_exit(2);
		if (cell_configure(a, CELL_SET_BINARY, "ids", &ids, sizeof(ids)))
			_exit(3);
		if (cell_configure(b, CELL_SET_BINARY, "ids", &ids, sizeof(ids)) != -1 ||
		    errno != ENOSPC)
			_exit(4);
		_exit(0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
	ASSERT_EQ(write_file("/proc/sys/user/max_cell_id_blocks", "4095"), 0);
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
	pidfd = prepare(self->c.cfd, "dirfd", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, host), 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);
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
	ASSERT_EQ(cell_kill(a, 0), 0);
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

TEST_HARNESS_MAIN
