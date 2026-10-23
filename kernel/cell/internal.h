/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _KERNEL_CELL_INTERNAL_H
#define _KERNEL_CELL_INTERNAL_H

#include <linux/cell.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/uidgid.h>
#include <linux/utsname.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#define CELL_KEY_MAX	64

struct cell {
	refcount_t		ref;
	u64			id;
	struct dentry		*stashed;

	struct mutex		lock;
	unsigned int		state;		/* enum cell_state */

	/* Gone once the cell is DEAD. */
	struct user_namespace	*user_ns;
	u32			ids_count;
	struct group_info	*groups;	/* of whoever made the cell */

	/* Slots. */
	struct mnt_namespace	*mnt_ns;
	struct pid_namespace	*pid_ns;
	struct net		*net;
	bool			no_net;		/* the slot was left empty */
	struct cgroup		*budget;
	u64			budget_id;
	kuid_t			budget_uid;	/* who owned it before */
	kgid_t			budget_gid;
	bool			sealed;		/* the budget was handed over */
	char			hostname[__NEW_UTS_LEN + 1];

	/* What sealing makes of them. */
	struct nsproxy		*nsproxy;
	struct path		root;

	int			exit_status;
	wait_queue_head_t	wait;
	struct work_struct	kill_work;
	struct delayed_work	exit_work;
	struct rcu_head		rcu;
};

static inline struct cell *cell_from_fd(const struct fd *f)
{
	if (fd_empty(*f))
		return ERR_PTR(-EBADF);
	return cell_from_file(fd_file(*f)) ?: ERR_PTR(-EINVAL);
}

/* ids.c */
int cell_set_ids(struct cell *cell, u32 count);

#endif /* _KERNEL_CELL_INTERNAL_H */
