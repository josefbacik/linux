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
