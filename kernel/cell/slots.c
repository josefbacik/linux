// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cells: filling the slots of a cell, and sealing it.
 */
#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/mnt_namespace.h>
#include <linux/nsfs.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <net/net_namespace.h>
#include <uapi/linux/cell.h>

#include "internal.h"

/*
 * Slots. All of these run with cell->lock held and the cell BUILDING. Filling a
 * slot takes what using the object that goes into it would take: holding the
 * cellfd is authority over the cell, not over what is put into it.
 */

static int cell_set_hostname(struct cell *cell, const char *val)
{
	if (strlen(val) > __NEW_UTS_LEN)
		return -ENAMETOOLONG;
	strscpy(cell->hostname, val);
	return 0;
}

/* A cgroup2 directory. Judged against whoever fills the slot, here and now. */
static int cell_set_budget(struct cell *cell, struct file *file)
{
	struct cgroup *cgrp;

	if (cell->budget)
		return -EBUSY;
	cgrp = cgroup_cell_budget_get(file, &cell->budget_uid, &cell->budget_gid);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);
	cell->budget = cgrp;
	cell->budget_id = cgroup_id(cgrp);
	return 0;
}

static struct ns_common *cell_ns_from_file(struct file *file, int type)
{
	struct ns_common *ns;

	if (!proc_ns_file(file))
		return ERR_PTR(-EINVAL);
	ns = get_proc_ns(file_inode(file));
	if (ns->ns_type != type)
		return ERR_PTR(-EINVAL);
	return ns;
}

/* A mount namespace that nobody has entered, which sealing sees to. */
static int cell_set_root(struct cell *cell, struct file *file)
{
	struct ns_common *ns = cell_ns_from_file(file, CLONE_NEWNS);

	if (IS_ERR(ns))
		return PTR_ERR(ns);
	if (cell->mnt_ns)
		return -EBUSY;
	if (!mnt_ns_may_claim(ns))
		return -EPERM;
	cell->mnt_ns = mnt_ns_get_from_common(ns);
	return 0;
}

static int cell_make_net(struct cell *cell)
{
	struct net *net;

	if (cell->net)
		return 0;
	net = copy_net_ns(CLONE_NEWNET, cell->user_ns, current->nsproxy->net_ns);
	if (IS_ERR(net))
		return PTR_ERR(net);
	cell->net = net;
	return 0;
}

/* "new": a network namespace of its own, which is also the default. */
static int cell_set_net_string(struct cell *cell, const char *val)
{
	if (strcmp(val, "new"))
		return -EINVAL;
	if (cell->net)
		return -EBUSY;
	return cell_make_net(cell);
}

/*
 * A network namespace to share. A file descriptor on one is no authority over
 * it, so it takes CAP_SYS_ADMIN over its owner. That is half of what setns()
 * asks for. The other half is about the namespaces of the caller, which do not
 * change here. And it is not that of another cell, whose tasks have every
 * capability over it. In whatever state that cell is: a slot outlives it.
 */
static int cell_set_net(struct cell *cell, struct file *file)
{
	struct ns_common *ns = cell_ns_from_file(file, CLONE_NEWNET);

	if (IS_ERR(ns))
		return PTR_ERR(ns);
	if (cell->net)
		return -EBUSY;
	if (!ns_capable(to_net_ns(ns)->user_ns, CAP_SYS_ADMIN) ||
	    userns_is_cell(to_net_ns(ns)->user_ns))
		return -EPERM;
	cell->net = get_net(to_net_ns(ns));
	return 0;
}

static int cell_set_ids_binary(struct cell *cell, const void __user *uvalue,
			       size_t len)
{
	u32 count;

	if (len != sizeof(count))
		return -EINVAL;
	if (copy_from_user(&count, uvalue, sizeof(count)))
		return -EFAULT;
	return cell_set_ids(cell, count);
}

static int cell_set_string(struct cell *cell, const char *key, const char *val)
{
	if (!strcmp(key, "hostname"))
		return cell_set_hostname(cell, val);
	if (!strcmp(key, "net"))
		return cell_set_net_string(cell, val);
	return -EINVAL;
}

static int cell_set_binary(struct cell *cell, const char *key,
			   const void __user *uvalue, size_t len)
{
	if (!strcmp(key, "ids"))
		return cell_set_ids_binary(cell, uvalue, len);
	return -EINVAL;
}

static int cell_set_fd(struct cell *cell, const char *key, struct file *file)
{
	if (!strcmp(key, "budget"))
		return cell_set_budget(cell, file);
	if (!strcmp(key, "root"))
		return cell_set_root(cell, file);
	if (!strcmp(key, "net"))
		return cell_set_net(cell, file);
	return -EINVAL;
}

static int cell_make_pid_ns(struct cell *cell)
{
	struct pid_namespace *ns;

	if (cell->pid_ns)
		return 0;
	ns = copy_pid_ns(CLONE_NEWPID, cell->user_ns, task_active_pid_ns(current));
	if (IS_ERR(ns))
		return PTR_ERR(ns);
	cell->pid_ns = ns;
	return 0;
}

/*
 * Everything that can fail comes before the mount namespace, which is changed
 * in place and cannot be changed back. If it fails the cell is still BUILDING.
 * What was filled in for slots that were left empty stays filled in.
 */
static int cell_seal(struct cell *cell)
{
	struct cgroup_namespace *cgroup_ns;
	struct nsproxy *nsproxy;
	kuid_t root_uid;
	kgid_t root_gid;
	int ret;

	if (!cell->budget || !cell->mnt_ns)
		return -EINVAL;

	if (!cell->ids_count) {
		ret = cell_set_ids(cell, 1);
		if (ret)
			return ret;
	}
	ret = cell_make_pid_ns(cell);
	if (ret)
		return ret;
	ret = cell_make_net(cell);
	if (ret)
		return ret;

	cgroup_ns = cgroup_cell_ns(cell->user_ns, cell->budget);
	if (IS_ERR(cgroup_ns))
		return PTR_ERR(cgroup_ns);

	nsproxy = cell_create_nsproxy(cell->user_ns, cell->mnt_ns, cell->pid_ns,
				      cell->net, cgroup_ns, cell->hostname);
	put_cgroup_ns(cgroup_ns);
	if (IS_ERR(nsproxy))
		return PTR_ERR(nsproxy);

	/* The builder cannot name the cell's ids, so it cannot do this. */
	if (cell->ids_count == 1) {
		root_uid = cell->user_ns->owner;
		root_gid = cell->user_ns->group;
	} else {
		root_uid = make_kuid(cell->user_ns, 0);
		root_gid = make_kgid(cell->user_ns, 0);
	}
	ret = cgroup_cell_chown(cell->budget, root_uid, root_gid);
	if (ret)
		goto out_chown;

	/* Two references: the slot's and the nsproxy's. */
	ret = mnt_ns_seal_for_cell(cell->mnt_ns, 2, cell->user_ns,
				   cell->ids_count > 1, &cell->root);
	if (ret)
		goto out_chown;

	cell->nsproxy = nsproxy;
	cell->sealed = true;
	WRITE_ONCE(cell->state, CELL_SEALED);
	return 0;

out_chown:
	cgroup_cell_chown(cell->budget, cell->budget_uid, cell->budget_gid);
	put_nsproxy(nsproxy);
	return ret;
}

/**
 * sys_cell_configure - change a cell
 * @cfd:    a cellfd
 * @cmd:    one of enum cell_configure_cmd
 * @ukey:   the name of what is set, or NULL for the commands that take none
 * @uvalue: a string for CELL_SET_STRING, @aux bytes for CELL_SET_BINARY
 * @aux:    a length for CELL_SET_BINARY, a file descriptor for CELL_SET_FD
 *
 * Shaped like fsconfig(). Data only goes in. Holding @cfd is all the authority
 * it takes over the cell. Filling a slot also takes what using the object that
 * goes into it would take.
 *
 * Everything but CELL_CMD_KILL needs the cell to be in state CELL_BUILDING.
 *
 * Return: 0, -EBUSY if the cell is past CELL_BUILDING or the slot is taken,
 * -EOPNOTSUPP for an unknown @cmd or a reserved key, -EINVAL for an unknown key
 * or arguments that do not go with @cmd, or what the slot has to say.
 */
SYSCALL_DEFINE5(cell_configure, int, cfd, unsigned int, cmd,
		const char __user *, ukey, const void __user *, uvalue, int, aux)
{
	char *key __free(kfree) = NULL;
	char *str __free(kfree) = NULL;
	struct cell *cell;

	CLASS(fd, f)(cfd);
	cell = cell_from_fd(&f);
	if (IS_ERR(cell))
		return PTR_ERR(cell);

	switch (cmd) {
	case CELL_SET_FLAG:
		if (!ukey || uvalue || aux)
			return -EINVAL;
		break;
	case CELL_SET_STRING:
		if (!ukey || !uvalue || aux)
			return -EINVAL;
		break;
	case CELL_SET_BINARY:
		if (!ukey || !uvalue || aux <= 0)
			return -EINVAL;
		break;
	case CELL_SET_FD:
		if (!ukey || uvalue || aux < 0)
			return -EINVAL;
		break;
	case CELL_CMD_SEAL:
		if (ukey || uvalue || aux)
			return -EINVAL;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (ukey) {
		key = strndup_user(ukey, CELL_KEY_MAX);
		if (IS_ERR(key))
			return PTR_ERR(no_free_ptr(key));
	}
	/* Reserved. See cell_may_spawn(). */
	if (key && !strcmp(key, "spawn"))
		return -EOPNOTSUPP;
	if (cmd == CELL_SET_STRING) {
		str = strndup_user(uvalue, 256);
		if (IS_ERR(str))
			return PTR_ERR(no_free_ptr(str));
	}

	guard(mutex)(&cell->lock);

	if (cell->state != CELL_BUILDING)
		return -EBUSY;

	switch (cmd) {
	case CELL_SET_FLAG:
		/* There are none yet. */
		return -EINVAL;
	case CELL_SET_STRING:
		return cell_set_string(cell, key, str);
	case CELL_SET_BINARY:
		return cell_set_binary(cell, key, uvalue, aux);
	case CELL_SET_FD: {
		CLASS(fd_raw, slot)(aux);

		if (fd_empty(slot))
			return -EBADF;
		return cell_set_fd(cell, key, fd_file(slot));
	}
	case CELL_CMD_SEAL:
		return cell_seal(cell);
	}
	return -EOPNOTSUPP;
}
