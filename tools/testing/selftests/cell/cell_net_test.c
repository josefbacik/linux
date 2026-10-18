// SPDX-License-Identifier: GPL-2.0
/*
 * Cells: the network. It is set up from the outside and handed to the cell, as
 * the tree is. A cell configures nothing unless it was built to.
 */
#include "cell_test.h"
#include <netinet/in.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

#define HOST_IP		0x0a090001	/* 10.9.0.1 */
#define CELL_IP		0x0a090002
#define LATER_IP	0x0a090003

static int set_cred(int pidfd, unsigned int id)
{
	struct pidfd_cred cred = { .uid = id, .gid = id };

	return pidfd_configure(pidfd, PIDFD_SET_BINARY, "cred", &cred, sizeof(cred));
}

/* Build a cell, run one thing in it as @id to its end. Returns its status. */
static int run(const struct build *b, unsigned int id, const char *what, const char *arg)
{
	struct cellctx c;
	int pidfd, st;

	st = cell_build(&c, b);
	if (st) {
		cell_cleanup(&c);
		return -100 - st;
	}
	pidfd = prepare(c.cfd, what, arg, NULL);
	if (pidfd < 0 || (id && set_cred(pidfd, id)) ||
	    pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0))
		st = -99;
	else
		st = cell_wait_dead(c.cfd);
	close(pidfd);
	cell_cleanup(&c);
	return st;
}

static int dev_up(const char *dev, unsigned int ip)
{
	struct ifreq ifr = {};
	struct sockaddr_in *sin = (void *)&ifr.ifr_addr;
	int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), r;

	strcpy(ifr.ifr_name, dev);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(ip);
	r = ioctl(s, SIOCSIFADDR, &ifr);
	sin->sin_addr.s_addr = htonl(0xffffff00);
	r = r ?: ioctl(s, SIOCSIFNETMASK, &ifr);
	r = r ?: ioctl(s, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_UP;
	r = r ?: ioctl(s, SIOCSIFFLAGS, &ifr);
	r = r ? -errno : 0;
	close(s);
	return r;
}

/* The same in the network namespace @net. Comes back. */
static int dev_up_in(int net, const char *dev, unsigned int ip)
{
	int old = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC), r;

	if (setns(net, CLONE_NEWNET))
		return -errno;
	r = dev_up(dev, ip);
	if (setns(old, CLONE_NEWNET))
		return -errno;
	close(old);
	return r;
}

static int sysctl_in(int net, const char *path, const char *val)
{
	int old = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC), r;

	if (setns(net, CLONE_NEWNET))
		return -errno;
	r = write_file(path, val) ? -errno : 0;
	if (setns(old, CLONE_NEWNET))
		return -errno;
	close(old);
	return r;
}

/* A network namespace of the caller's own making, with nothing done to it. */
static int make_netns(void)
{
	int old = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC), net;

	if (old < 0 || unshare(CLONE_NEWNET))
		return -1;
	net = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (setns(old, CLONE_NEWNET))
		return -1;
	close(old);
	return net;
}

static struct rtattr *put_attr(struct nlmsghdr *h, int type, const void *data, int len)
{
	struct rtattr *a = (void *)((char *)h + NLMSG_ALIGN(h->nlmsg_len));

	a->rta_type = type;
	a->rta_len = RTA_LENGTH(len);
	if (data)
		memcpy(RTA_DATA(a), data, len);
	h->nlmsg_len = NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(a->rta_len);
	return a;
}

static void end_nest(struct nlmsghdr *h, struct rtattr *a)
{
	a->rta_len = (char *)h + NLMSG_ALIGN(h->nlmsg_len) - (char *)a;
}

/* vh0 here, vc0 in the network namespace @net. */
static int make_veth(int net)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct {
		struct nlmsghdr h;
		struct ifinfomsg i;
		char attrs[256];
	} req = {};
	struct rtattr *info, *data, *peer;
	struct nlmsghdr *h;
	char buf[1024];
	int s, n;

	req.h.nlmsg_type = RTM_NEWLINK;
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	put_attr(&req.h, IFLA_IFNAME, "vh0", 4);
	info = put_attr(&req.h, IFLA_LINKINFO, NULL, 0);
	put_attr(&req.h, IFLA_INFO_KIND, "veth", 5);
	data = put_attr(&req.h, IFLA_INFO_DATA, NULL, 0);
	peer = put_attr(&req.h, VETH_INFO_PEER, NULL, sizeof(struct ifinfomsg));
	put_attr(&req.h, IFLA_IFNAME, "vc0", 4);
	put_attr(&req.h, IFLA_NET_NS_FD, &net, sizeof(net));
	end_nest(&req.h, peer);
	end_nest(&req.h, data);
	end_nest(&req.h, info);

	s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (s < 0 || sendto(s, &req, req.h.nlmsg_len, 0, (void *)&sa, sizeof(sa)) < 0)
		return -errno;
	n = recv(s, buf, sizeof(buf), 0);
	close(s);
	h = (void *)buf;
	if (n < (int)sizeof(*h) || h->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;
	return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
}

/*
 * Nothing was said about the network, so there is none. What the cell is handed
 * works all the same: here a socket that listens in the network of the host.
 */
TEST_F(cell, no_net_slot_no_network)
{
	static const unsigned int ids[] = { 0, 1000 };
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(7778),
				 .sin_addr = { htonl(INADDR_LOOPBACK) } };
	int lsock, conn, pidfd, one = 1;
	unsigned int i;
	char c = 0;

	ASSERT_EQ(dev_up("lo", INADDR_LOOPBACK), 0);
	lsock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	ASSERT_EQ(bind(lsock, (void *)&a, sizeof(a)), 0);
	ASSERT_EQ(listen(lsock, 1), 0);

	for (i = 0; i < ARRAY_SIZE(ids); i++) {
		struct cellctx cell;

		ASSERT_EQ(cell_build(&cell, &(struct build){ .ids = 65536 }), 0);
		pidfd = prepare(cell.cfd, "net-none", NULL, NULL);
		ASSERT_GE(pidfd, 0);
		if (ids[i])
			ASSERT_EQ(set_cred(pidfd, ids[i]), 0);
		ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, lsock), 0);
		ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);

		conn = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		ASSERT_EQ(connect(conn, (void *)&a, sizeof(a)), 0);
		EXPECT_EQ(write(conn, "h", 1), 1);
		EXPECT_EQ(read(conn, &c, 1), 1);
		EXPECT_EQ(c, 'c');
		close(conn);

		EXPECT_EQ(cell_wait_dead(cell.cfd), 0);
		close(pidfd);
		cell_cleanup(&cell);
	}
	close(lsock);
}

static int seal(int cfd)
{
	return cell_configure(cfd, CELL_CMD_SEAL, NULL, NULL, 0);
}

static int run_sealed(struct cellctx *c, const char *what, const char *arg)
{
	int pidfd = spawn(c->cfd, NULL, what, arg, NULL), st;

	if (pidfd < 0)
		return -99;
	st = cell_wait_dead(c->cfd);
	close(pidfd);
	return st;
}

/* A seal that fails before there is a network namespace has decided nothing. */
TEST_F(cell, failed_seal_leaves_the_net_slot_open)
{
	char max[32] = {};
	int fd;

	fd = open("/proc/sys/user/max_net_namespaces", O_RDONLY);
	ASSERT_GE(fd, 0);
	ASSERT_GT(read(fd, max, sizeof(max) - 1), 0);
	close(fd);

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true }), 0);
	ASSERT_EQ(write_file("/proc/sys/user/max_net_namespaces", "0"), 0);
	EXPECT_EQ(seal(self->c.cfd), -1);
	EXPECT_EQ(errno, ENOSPC);
	ASSERT_EQ(write_file("/proc/sys/user/max_net_namespaces", max), 0);

	ASSERT_EQ(cell_configure(self->c.cfd, CELL_SET_STRING, "net", "new", 0), 0);
	ASSERT_EQ(seal(self->c.cfd), 0);
	EXPECT_EQ(run_sealed(&self->c, "net-at-all", "yes"), 0);
}

/* Makes the next seal fail late, with EBUSY: somebody is in the mount namespace. */
static pid_t sit_in(int rootfd)
{
	int ready[2];
	pid_t pid;
	char c;

	if (pipe2(ready, O_CLOEXEC))
		return -1;
	pid = fork();
	if (!pid) {
		if (setns(rootfd, CLONE_NEWNS) || write(ready[1], "r", 1) != 1)
			_exit(1);
		for (;;)
			pause();
	}
	close(ready[1]);
	if (read(ready[0], &c, 1) != 1)
		pid = -1;
	close(ready[0]);
	return pid;
}

static int seal_once_free(int cfd, pid_t sitter)
{
	int i, r = -1;

	kill(sitter, SIGKILL);
	waitpid(sitter, NULL, 0);
	for (i = 0; i < 100 && (r = seal(cfd)) && errno == EBUSY; i++)
		usleep(20000);
	return r;
}

/* One that fails later has filled the slot in. No network is what it stays. */
TEST_F(cell, failed_seal_then_still_no_network)
{
	pid_t sitter;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true,
							.keep_root = true }), 0);
	sitter = sit_in(self->c.rootfd);
	ASSERT_GT(sitter, 0);
	EXPECT_EQ(seal(self->c.cfd), -1);
	EXPECT_EQ(errno, EBUSY);
	EXPECT_EQ(cell_configure(self->c.cfd, CELL_SET_STRING, "net", "own", 0), -1);
	EXPECT_EQ(errno, EBUSY);
	ASSERT_EQ(seal_once_free(self->c.cfd, sitter), 0);
	EXPECT_EQ(run_sealed(&self->c, "net-at-all", "no"), 0);
}

/* Unless the builder asks for it after all, to set it up. */
TEST_F(cell, failed_seal_then_a_network_after_all)
{
	pid_t sitter;
	int net;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .no_seal = true,
							.keep_root = true }), 0);
	sitter = sit_in(self->c.rootfd);
	ASSERT_GT(sitter, 0);
	EXPECT_EQ(seal(self->c.cfd), -1);
	EXPECT_EQ(errno, EBUSY);
	net = cell_open(self->c.cfd, CELL_OPEN_SLOT, "net", NULL, 0);
	ASSERT_GE(net, 0);
	ASSERT_EQ(dev_up_in(net, "lo", INADDR_LOOPBACK), 0);
	close(net);
	ASSERT_EQ(seal_once_free(self->c.cfd, sitter), 0);
	EXPECT_EQ(run_sealed(&self->c, "net-lo", NULL), 0);
}

/* "new" is one for whoever builds the cell to set up. Until then there is little to it. */
TEST_F(cell, new_net_is_the_builders_to_set_up)
{
	int net, pidfd;

	EXPECT_EQ(run(&(struct build){ .ids = 65536, .net_str = "new" }, 0, "net-bare", NULL), 0);

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .net_str = "new",
							.no_seal = true }), 0);
	net = cell_open(self->c.cfd, CELL_OPEN_SLOT, "net", NULL, 0);
	ASSERT_GE(net, 0);
	ASSERT_EQ(dev_up_in(net, "lo", INADDR_LOOPBACK), 0);
	ASSERT_EQ(cell_configure(self->c.cfd, CELL_CMD_SEAL, NULL, NULL, 0), 0);
	pidfd = spawn(self->c.cfd, NULL, "net-lo", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	EXPECT_EQ(cell_wait_dead(self->c.cfd), 0);
	close(pidfd);
	close(net);
}

/*
 * What an orchestrator does: it makes the network namespace, puts one end of a
 * veth pair in there, gives it an address, and goes on owning all of it. The cell
 * uses it, and its root can change nothing about it.
 */
TEST_F(cell, net_is_set_up_from_the_outside)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(7777),
				 .sin_addr = { htonl(HOST_IP) } };
	int net, lsock, conn, up[2], down[2], pidfd, one = 1, r;
	char c = 0;

	net = make_netns();
	ASSERT_GE(net, 0);
	r = make_veth(net);
	if (r == -EOPNOTSUPP) {
		close(net);
		SKIP(return, "no veth");
	}
	ASSERT_EQ(r, 0);
	ASSERT_EQ(dev_up("vh0", HOST_IP), 0);
	ASSERT_EQ(dev_up_in(net, "lo", INADDR_LOOPBACK), 0);
	ASSERT_EQ(dev_up_in(net, "vc0", CELL_IP), 0);

	lsock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	ASSERT_EQ(bind(lsock, (void *)&a, sizeof(a)), 0);
	ASSERT_EQ(listen(lsock, 1), 0);

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .net = net }), 0);
	ASSERT_EQ(pipe2(up, O_CLOEXEC), 0);
	ASSERT_EQ(pipe2(down, O_CLOEXEC), 0);
	pidfd = prepare(self->c.cfd, "net-given", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "3", NULL, up[1]), 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_SET_FD, "4", NULL, down[0]), 0);
	ASSERT_EQ(pidfd_configure(pidfd, PIDFD_CMD_START, NULL, NULL, 0), 0);

	conn = accept(lsock, NULL, NULL);
	ASSERT_GE(conn, 0);
	EXPECT_EQ(read(conn, &c, 1), 1);
	EXPECT_EQ(c, 'c');
	EXPECT_EQ(write(conn, "h", 1), 1);

	/* The cell is running. Whoever owns the namespace still gets at it. */
	ASSERT_EQ(read(up[0], &c, 1), 1);
	EXPECT_EQ(cell_state(self->c.cfd), CELL_RUNNING);
	EXPECT_EQ(dev_up_in(net, "lo", LATER_IP), 0);
	ASSERT_EQ(write(down[1], "g", 1), 1);

	EXPECT_EQ(cell_wait_dead(self->c.cfd), 0);
	close(pidfd);
	close(conn);
	close(lsock);
	close(net);
}

/* That of the host is no different: it is there to be used. */
TEST_F(cell, host_net_is_used_and_not_configured)
{
	int net = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);

	ASSERT_GE(net, 0);
	ASSERT_EQ(dev_up("lo", INADDR_LOOPBACK), 0);
	EXPECT_EQ(run(&(struct build){ .ids = 65536, .net = net }, 0, "net-lo", NULL), 0);
	close(net);
}

/* What a pod expects takes no capability: it is set on the network namespace. */
TEST_F(cell, low_ports_and_ping_are_settings)
{
	static const unsigned int ids[] = { 0, 1000 };
	unsigned int i;
	int net;

	net = make_netns();
	ASSERT_GE(net, 0);
	ASSERT_EQ(dev_up_in(net, "lo", INADDR_LOOPBACK), 0);
	for (i = 0; i < ARRAY_SIZE(ids); i++)
		EXPECT_EQ(run(&(struct build){ .ids = 65536, .net = net }, ids[i],
			      "net-settings", "before"), 0);

	ASSERT_EQ(sysctl_in(net, "/proc/sys/net/ipv4/ip_unprivileged_port_start", "0"), 0);
	ASSERT_EQ(sysctl_in(net, "/proc/sys/net/ipv4/ping_group_range", "0 4294967294"), 0);
	for (i = 0; i < ARRAY_SIZE(ids); i++)
		EXPECT_EQ(run(&(struct build){ .ids = 65536, .net = net }, ids[i],
			      "net-settings", "after"), 0);
	close(net);
}

/* Asked for, the cell owns its network namespace and its root runs it. */
TEST_F(cell, net_of_its_own_has_to_be_asked_for)
{
	struct build own = { .ids = 65536, .net_str = "own" };
	int cfd;

	EXPECT_EQ(run(&own, 0, "net-own", NULL), 0);
	/* Its root, and nobody else in there. */
	EXPECT_EQ(run(&own, 1000, "net-bare", NULL), 0);

	cfd = cell_create(CELL_SELF, 0);
	ASSERT_GE(cfd, 0);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_STRING, "net", "mine", 0), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_STRING, "net", "own", 0), 0);
	EXPECT_EQ(cell_configure(cfd, CELL_SET_STRING, "net", "new", 0), -1);
	EXPECT_EQ(errno, EBUSY);
	close(cfd);
}

/*
 * A network namespace that was made for a cell is not the cell's, so who owns it
 * may enter it whatever the cell is up to, and may share it with another cell.
 */
TEST_F(cell, new_net_belongs_to_the_builder)
{
	int net, old, other, pidfd;
	char path[64];
	pid_t pid;

	ASSERT_EQ(cell_build(&self->c, &(struct build){ .ids = 65536, .net_str = "new" }), 0);
	pidfd = spawn(self->c.cfd, &pid, "pause", NULL, NULL);
	ASSERT_GE(pidfd, 0);
	snprintf(path, sizeof(path), "/proc/%d/ns/net", pid);
	net = open(path, O_RDONLY | O_CLOEXEC);
	ASSERT_GE(net, 0);

	old = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	EXPECT_EQ(setns(net, CLONE_NEWNET), 0);
	ASSERT_EQ(setns(old, CLONE_NEWNET), 0);
	close(old);

	other = cell_create(CELL_SELF, 0);
	ASSERT_GE(other, 0);
	EXPECT_EQ(cell_configure(other, CELL_SET_FD, "net", NULL, net), 0);
	close(other);
	close(net);
	close(pidfd);
}

/* A builder without privilege works in a user namespace of its own, which owns it. */
TEST_F(cell, unprivileged_builder_sets_up_the_net)
{
	int status;
	pid_t pid;

	ASSERT_EQ(chown(CGROOT, 1000, 1000), 0);
	ASSERT_EQ(chown(CGROOT "/cgroup.procs", 1000, 1000), 0);
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		struct cellctx c;
		pid_t helper;
		int step, net;

		if (setgroups(0, NULL) || setresgid(1000, 1000, 1000) ||
		    setresuid(1000, 1000, 1000) || prctl(PR_SET_DUMPABLE, 1, 0, 0, 0))
			_exit(1);
		if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
			_exit(2);
		if (write_file("/proc/self/setgroups", "deny") ||
		    write_file("/proc/self/uid_map", "1000 1000 1") ||
		    write_file("/proc/self/gid_map", "1000 1000 1"))
			_exit(3);
		step = cell_build(&c, &(struct build){ .ids = 1, .no_seal = true });
		if (step)
			_exit(20 + step);
		net = cell_open(c.cfd, CELL_OPEN_SLOT, "net", NULL, 0);
		if (net < 0)
			_exit(4);
		/* There is no way back to the network namespace of the host. */
		helper = fork();
		if (!helper)
			_exit(setns(net, CLONE_NEWNET) || dev_up("lo", INADDR_LOOPBACK) ? 1 : 0);
		if (waitpid(helper, &step, 0) != helper || step)
			_exit(5);
		if (cell_configure(c.cfd, CELL_CMD_SEAL, NULL, NULL, 0))
			_exit(6);
		if (spawn(c.cfd, NULL, "net-lo", NULL, NULL) < 0)
			_exit(7);
		_exit(cell_wait(c.cfd) ? 8 : 0);
	}
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
	EXPECT_EQ(chown(CGROOT, 0, 0), 0);
	EXPECT_EQ(chown(CGROOT "/cgroup.procs", 0, 0), 0);
}

TEST_HARNESS_MAIN
