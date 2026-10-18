// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cells: the ids of a cell.
 */
#include <linux/bitmap.h>
#include <linux/key.h>
#include <linux/sched/user.h>
#include <linux/spinlock.h>
#include <linux/user_namespace.h>

#include "internal.h"

/*
 * The kuid block allocator.
 *
 * "Nobody else holds an id of this block" is what stands in for the privilege
 * check a legacy user namespace needs before it may map a range. So it is
 * enforced rather than assumed:
 *
 *  - a block lives as long as the user namespace object it was given to, which
 *    every credential, and every object owned by the namespace, pins;
 *  - no create, chown or ACL stores an id of the window in a filesystem the cell
 *    does not own, see kuid_storable();
 *  - a legacy user namespace cannot map into the window, see map_write();
 *  - an idmapping of a mount that was made for the cell pins the namespace too,
 *    see alloc_mnt_idmap();
 *  - a released block is quarantined, and goes back to the pool only once the
 *    tables that are keyed by bare kuid hold nothing in its range. The same is
 *    asked before a block is handed out.
 *
 * Blocks are handed out round robin so that reuse comes as late as it can. A
 * quarantined block counts as used: a leak shows up as -ENOSPC, never as one
 * tenant owning what another left behind.
 */
static DEFINE_SPINLOCK(cell_block_lock);
static DECLARE_BITMAP(cell_block_used, CELL_ID_NR_BLOCKS);
static DECLARE_BITMAP(cell_block_quarantine, CELL_ID_NR_BLOCKS);
static unsigned int cell_block_cursor;

static void cell_block_sweep(struct work_struct *work);
static DECLARE_DELAYED_WORK(cell_block_sweep_work, cell_block_sweep);

static inline u32 cell_block_first(u32 block)
{
	return CELL_ID_WINDOW_FIRST + block * CELL_ID_BLOCK_SIZE;
}

static int cell_block_take(void)
{
	unsigned int block;

	guard(spinlock)(&cell_block_lock);

	block = find_next_zero_bit(cell_block_used, CELL_ID_NR_BLOCKS,
				   cell_block_cursor);
	if (block >= CELL_ID_NR_BLOCKS)
		block = find_first_zero_bit(cell_block_used, CELL_ID_NR_BLOCKS);
	if (block >= CELL_ID_NR_BLOCKS)
		return -ENOSPC;

	__set_bit(block, cell_block_used);
	cell_block_cursor = (block + 1) % CELL_ID_NR_BLOCKS;
	return block;
}

/* Does anything that is keyed by a bare kuid still name an id of @block? */
static bool cell_block_busy(u32 block)
{
	kuid_t first = KUIDT_INIT(cell_block_first(block));
	kuid_t last = KUIDT_INIT(cell_block_first(block) + CELL_ID_BLOCK_SIZE - 1);

	return uid_range_in_use(first, last) || key_user_range_in_use(first, last);
}

/* Returns a block number, or a negative error. */
static int cell_block_alloc(void)
{
	int block, tries;

	for (tries = 0; tries < 64; tries++) {
		block = cell_block_take();
		if (block < 0 || !cell_block_busy(block))
			return block;
		/*
		 * Nothing keeps a task of the host from running on an id of the
		 * window. A block it does that in is not for lending.
		 */
		cell_block_release(block);
	}
	return -ENOSPC;
}

static void cell_block_sweep(struct work_struct *work)
{
	bool again = false;
	unsigned int block;

	for_each_set_bit(block, cell_block_quarantine, CELL_ID_NR_BLOCKS) {
		if (cell_block_busy(block)) {
			again = true;
			continue;
		}
		guard(spinlock)(&cell_block_lock);
		__clear_bit(block, cell_block_quarantine);
		__clear_bit(block, cell_block_used);
	}

	if (again)
		schedule_delayed_work(&cell_block_sweep_work, 10 * HZ);
}

/**
 * cell_block_release - the user namespace that was lent a block is gone
 * @block: the number of the block
 *
 * The block goes into quarantine. It returns to the pool once the sweep finds
 * nothing left that names one of its ids.
 *
 * Context: Process context.
 */
void cell_block_release(u32 block)
{
	scoped_guard(spinlock, &cell_block_lock)
		__set_bit(block, cell_block_quarantine);
	schedule_delayed_work(&cell_block_sweep_work, 0);
}

static int __init cell_init(void)
{
	/* No one user gets to use up the window. */
	init_user_ns.ucount_max[UCOUNT_CELL_ID_BLOCKS] = CELL_ID_NR_BLOCKS / 8;
	return 0;
}
late_initcall(cell_init);

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

/* A block gives access to nothing, but there are only so many. */
static int cell_set_id_block(struct cell *cell)
{
	struct user_namespace *ns = cell->user_ns;
	struct ucounts *ucounts;
	int block, ret;

	ucounts = inc_ucount(ns->parent, ns->owner, UCOUNT_CELL_ID_BLOCKS);
	if (!ucounts)
		return -ENOSPC;
	block = cell_block_alloc();
	if (block < 0) {
		dec_ucount(ucounts, UCOUNT_CELL_ID_BLOCKS);
		return block;
	}
	ret = userns_set_cell_map(ns, 0, cell_block_first(block),
				  0, cell_block_first(block),
				  CELL_ID_BLOCK_SIZE, block + 1, ucounts);
	if (ret) {
		cell_block_release(block);
		dec_ucount(ucounts, UCOUNT_CELL_ID_BLOCKS);
	}
	return ret;
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
	case CELL_ID_BLOCK_SIZE:
		ret = cell_set_id_block(cell);
		break;
	default:
		return -EINVAL;
	}

	if (!ret)
		cell->ids_count = count;
	return ret;
}
