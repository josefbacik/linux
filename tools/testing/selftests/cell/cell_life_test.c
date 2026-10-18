// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for cells, the life of a cell: building one, killing one, handles, and
 * the races between them.
 */
#include "cell_test.h"

TEST_F(cell, life)
{
	struct cell_info info = { .mask = ~0ULL };
	struct pollfd pfd;
	pid_t pid;
	int pidfd;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true }), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_BUILDING);

	/* Not before it is sealed. */
	EXPECT_EQ(pidfd_open_empty(self->c.cfd, 0), -1);
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
	EXPECT_EQ(pidfd_open_empty(self->c.cfd, 0), -1);
	EXPECT_EQ(errno, ESRCH);
	EXPECT_EQ(cg_populated(self->c.cg), 0);
	close(pidfd);
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
	ASSERT_EQ(cell_kill(self->c.cfd, 0), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	EXPECT_EQ(cell_wait(self->c.cfd), SIGKILL);
	EXPECT_EQ(cell_configure(self->c.cfd, CELL_CMD_SEAL, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EBUSY);
	/* Idempotent. */
	EXPECT_EQ(cell_kill(self->c.cfd, 0), 0);
}

/* What cell_kill() takes, and that it works whatever state the cell is in. */
TEST_F(cell, kill_in_every_state)
{
	struct pollfd pfd;
	int fd, pidfd;

	EXPECT_EQ(cell_kill(-1, 0), -1);
	EXPECT_EQ(errno, EBADF);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	EXPECT_EQ(cell_kill(fd, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	close(fd);

	/* Sealed, nothing spawned. */
	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_SEALED);
	EXPECT_EQ(cell_kill(self->c.cfd, 1), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_SEALED);
	/* It is a system call of its own and no command of cell_configure(). */
	EXPECT_EQ(cell_configure(self->c.cfd, 5, NULL, NULL, 0), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_SEALED);
	EXPECT_EQ(cell_kill(self->c.cfd, 0), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	/* Dead. */
	EXPECT_EQ(cell_kill(self->c.cfd, 0), 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	cell_cleanup(&self->c);

	/* Running. */
	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536 }), 0);
	pidfd = spawn(self->c.cfd, NULL, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_RUNNING);
	EXPECT_EQ(cell_kill(self->c.cfd, 0), 0);
	/* Dying, or dead already. It does not wait. */
	EXPECT_EQ(cell_kill(self->c.cfd, 0), 0);
	pfd = (struct pollfd){ .fd = self->c.cfd, .events = POLLIN };
	EXPECT_EQ(poll(&pfd, 1, 10000), 1);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_DEAD);
	close(pidfd);
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

	ASSERT_EQ(cell_kill(self->c.cfd, 0), 0);
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
			int second = prepare(c.cfd, "pause", NULL, NULL);

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
						    prepare(c.cfd, "pause", NULL, NULL);

					if (p < 0)
						_exit(errno == ESRCH || errno == ENOMEM ||
						      errno == EINTR || errno == EBUSY ?
						      0 : 1);
					close(p);
				}
			}
		}
		usleep(1000 * (i % 7) * (i % 5));
		ASSERT_EQ(cell_kill(c.cfd, 0), 0);
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
		int pidfd = prepare(self->c.cfd, "exit", "0", NULL);
		int status;
		pid_t pid;

		ASSERT_GE(pidfd, 0);
		pid = fork();
		ASSERT_GE(pid, 0);
		if (!pid) {
			/* Both hold the one file. Only one start can win. */
			int r = pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0);

			_exit(!r || errno == EBUSY || errno == ESRCH ? 0 : 1);
		}
		if (i & 1)
			pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0);
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

		ASSERT_EQ(cell_build(&c, &(struct build){ .ids = 65536,
							  .no_seal = i % 4 == 0 }), 0);
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
