// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cells: the ids of a cell.
 */
#include <linux/user_namespace.h>

#include "internal.h"

/* The id of whoever made the cell, under its own number. */
static int cell_set_one_id(struct cell *cell)
{
	struct user_namespace *ns = cell->user_ns;

	/* Too much goes by the bare value of kuid 0, capabilities or none. */
	if (uid_eq(ns->owner, GLOBAL_ROOT_UID))
		return -EPERM;
	/* Nor an id of the window, as for a legacy user namespace. */
	if (cell_id_in_window(__kuid_val(ns->owner)) ||
	    cell_id_in_window(__kgid_val(ns->group)))
		return -EPERM;
	return userns_set_cell_map(ns,
				   from_kuid(ns->parent, ns->owner),
				   __kuid_val(ns->owner),
				   from_kgid(ns->parent, ns->group),
				   __kgid_val(ns->group), 1, 0, NULL);
}

/**
 * cell_set_ids - fill the "ids" slot
 * @cell:  a cell that is being built
 * @count: how many ids it is to have, 1 or CELL_ID_BLOCK_SIZE
 *
 * Context: The caller holds the lock of the cell.
 * Return: 0, -EBUSY if the slot is taken, -EINVAL for any other @count, -EPERM
 * if whoever made the cell cannot have a cell of one id, -ENOSPC if there is no
 * block to be had.
 */
int cell_set_ids(struct cell *cell, u32 count)
{
	int ret;

	if (cell->ids_count)
		return -EBUSY;

	switch (count) {
	case 1:
		ret = cell_set_one_id(cell);
		break;
	default:
		return -EINVAL;
	}

	if (!ret)
		cell->ids_count = count;
	return ret;
}
