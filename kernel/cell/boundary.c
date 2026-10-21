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
 * Nobody enters a cell. The one exception is a network namespace that the cell
 * owns, while the cell is still being built, which is how the tools that
 * configure networks work today. Not the pid namespace: whoever got in there
 * could become the init of the cell, or hold on to it and fork into the cell
 * later.
 *
 * The mount namespace of a cell is owned by the user namespace of whoever built
 * it and looks after itself, see mnt_ns_seal_for_cell(). So is its network
 * namespace unless the cell was built to own one, and that is not the cell's to
 * begin with: whoever set it up may go on doing so.
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

/**
 * cell_may_change_cgroup - may the caller change a cgroup?
 * @cgrp: the cgroup
 *
 * A task of a cell changes nothing outside of the budget of the cell, whatever
 * the modes say and whoever owns the cgroup, which a cell of one id does if its
 * maker does. It writes to no file, makes, removes and renames no cgroup, and
 * sets no mode, owner, time or extended attribute. See cgroup_may_change() for
 * where this is asked.
 *
 * What it makes is owned by ids that were only lent to the cell. Some of that is
 * made without the filesystem being asked whether it can store the id, such as
 * the files that enabling a controller adds to the children of a cgroup. So it
 * has to be where it goes with the cell, see cgroup_cell_budget_put().
 *
 * It goes by who is asking and not by who opened the file, which may have been
 * handed to the cell.
 *
 * Return: true if the caller is in no cell, or @cgrp is the budget of its cell or
 * lies below it.
 */
bool cell_may_change_cgroup(struct cgroup *cgrp)
{
	return cell_may_migrate(current, cgrp);
}
