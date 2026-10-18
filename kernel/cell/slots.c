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

static int cell_set_string(struct cell *cell, const char *key, const char *val)
{
	if (!strcmp(key, "hostname"))
		return cell_set_hostname(cell, val);
	return -EINVAL;
}

static int cell_set_binary(struct cell *cell, const char *key,
			   const void __user *uvalue, size_t len)
{
	return -EINVAL;
}

static int cell_set_fd(struct cell *cell, const char *key, struct file *file)
{
	return -EINVAL;
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
 * All of it needs the cell to be in state CELL_BUILDING.
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
	default:
		return -EOPNOTSUPP;
	}

	if (ukey) {
		key = strndup_user(ukey, CELL_KEY_MAX);
		if (IS_ERR(key))
			return PTR_ERR(no_free_ptr(key));
	}
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
	}
	return -EOPNOTSUPP;
}
