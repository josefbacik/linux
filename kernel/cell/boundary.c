// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cells: what other subsystems ask about the boundary of a cell.
 */
#include <linux/cgroup.h>
#include <linux/ns_common.h>
#include <linux/user_namespace.h>
#include <uapi/linux/cell.h>

#include "internal.h"

/**
 * cell_ns_may_enter - may somebody enter a namespace with setns()?
 * @ns:    the namespace
 * @owner: the user namespace that owns @ns
 *
 * Nobody enters a cell. The one exception is the network namespace of a cell
 * that is still being built, which is how the tools that configure networks
 * work today. Not the pid namespace: whoever got in there could become the
 * init of the cell, or hold on to it and fork into the cell later.
 *
 * The mount namespace of a cell is owned by the user namespace of whoever built
 * it and looks after itself, see mnt_ns_seal_for_cell().
 *
 * Return: true if @owner is not the user namespace of a cell, or the exception
 * applies.
 */
bool cell_ns_may_enter(const struct ns_common *ns,
		       const struct user_namespace *owner)
{
	struct cell *cell = owner->cell;

	if (!cell)
		return true;
	return ns->ns_type == CLONE_NEWNET &&
	       READ_ONCE(cell->state) == CELL_BUILDING;
}

/**
 * cell_idmap_userns - the user namespace to idmap a mount with, by cellfd
 * @file: what was passed in mount_attr.userns_fd
 *
 * A cellfd there means "for this cell". It works while the cell is being built
 * and once its ids have been set.
 *
 * Return: the user namespace of the cell with a reference, NULL if @file is no
 * cellfd, or an ERR_PTR().
 */
struct user_namespace *cell_idmap_userns(const struct file *file)
{
	struct cell *cell = cell_from_file(file);

	if (!cell)
		return NULL;

	guard(mutex)(&cell->lock);
	if (cell->state != CELL_BUILDING)
		return ERR_PTR(-EBUSY);
	if (!cell->ids_count)
		return ERR_PTR(-EINVAL);
	return get_user_ns(cell->user_ns);
}

/**
 * cell_may_migrate - may a task be moved to a cgroup?
 * @task: the task
 * @dst:  the cgroup
 *
 * A task of a cell stays within the budget of the cell, whoever asks. On a
 * hierarchy other than that of the budget no request moves it from where it was
 * born. This is asked for every request. It is not asked when the kernel itself
 * empties a legacy cpuset that lost its last cpu, see cgroup_transfer_tasks(),
 * which works on legacy hierarchies only and so never touches a budget.
 *
 * Return: true if @task is in no cell, or @dst is the budget of its cell or
 * lies below it.
 */
bool cell_may_migrate(struct task_struct *task, struct cgroup *dst)
{
	struct cgroup *budget;
	struct cell *cell;

	guard(rcu)();
	cell = task_cell(task);
	if (!cell)
		return true;
	budget = READ_ONCE(cell->budget);
	return budget && cgroup_is_descendant(dst, budget);
}
