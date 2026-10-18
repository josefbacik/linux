/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CELL_IDS_H
#define _LINUX_CELL_IDS_H

#include <linux/compiler.h>
#include <linux/limits.h>
#include <linux/uidgid.h>

struct user_namespace;

/*
 * The kernel hands every multi-id cell a block of kuids and kgids out of this
 * window. Nobody else may hold an id in it: a legacy user namespace cannot map
 * into it, and no create, chown or ACL stores one in a filesystem that the cell
 * it was lent to does not own.
 *
 * The last block is left out so that (uid_t)-1 stays clear of it.
 */
#define CELL_ID_BLOCK_SIZE	65536U
#define CELL_ID_WINDOW_FIRST	0x80000000U
#define CELL_ID_WINDOW_LAST	0xfffeffffU
#define CELL_ID_NR_BLOCKS	\
	((CELL_ID_WINDOW_LAST - CELL_ID_WINDOW_FIRST + 1) / CELL_ID_BLOCK_SIZE)

#ifdef CONFIG_CELLS

/**
 * cell_id_in_window - is an id one of those the kernel lends to cells?
 * @id: the value of a kuid or kgid
 *
 * Return: true if it is.
 */
static inline bool cell_id_in_window(u32 id)
{
	return id >= CELL_ID_WINDOW_FIRST && id <= CELL_ID_WINDOW_LAST;
}

/**
 * cell_range_in_window - does a range of ids touch the window?
 * @first: the value of the first kuid or kgid of the range
 * @count: how many there are
 *
 * Return: true if any id of the range lies in the window.
 */
static inline bool cell_range_in_window(u32 first, u32 count)
{
	u32 last = first + count - 1;

	if (!count)
		return false;
	if (last < first)
		last = U32_MAX;
	return first <= CELL_ID_WINDOW_LAST && last >= CELL_ID_WINDOW_FIRST;
}

bool userns_is_cell(const struct user_namespace *ns);

#else

static inline bool cell_id_in_window(u32 id) { return false; }
static inline bool cell_range_in_window(u32 first, u32 count) { return false; }
static inline bool userns_is_cell(const struct user_namespace *ns) { return false; }

#endif

/**
 * kuid_storable - may a filesystem store a kuid?
 * @fs_userns: the user namespace of the filesystem, sb->s_user_ns
 * @kuid:      the kuid, after the idmapping of the mount has been applied
 *
 * An id that was lent to a cell must not outlive the loan, so it never reaches
 * a filesystem that the cell does not own. Through a mount that is idmapped for
 * the cell the id has become the on-disk one long before it gets here.
 *
 * That @kuid is an id of this cell and not of another is for the caller's usual
 * kuid_has_mapping() to say.
 *
 * Return: true if @kuid is outside of the window, or @fs_userns is the user
 * namespace of a cell.
 */
static inline bool kuid_storable(const struct user_namespace *fs_userns, kuid_t kuid)
{
	return likely(!cell_id_in_window(__kuid_val(kuid))) ||
	       userns_is_cell(fs_userns);
}

/**
 * kgid_storable - may a filesystem store a kgid?
 * @fs_userns: the user namespace of the filesystem, sb->s_user_ns
 * @kgid:      the kgid, after the idmapping of the mount has been applied
 *
 * See kuid_storable().
 *
 * Return: true if @kgid is outside of the window, or @fs_userns is the user
 * namespace of a cell.
 */
static inline bool kgid_storable(const struct user_namespace *fs_userns, kgid_t kgid)
{
	return likely(!cell_id_in_window(__kgid_val(kgid))) ||
	       userns_is_cell(fs_userns);
}

#endif /* _LINUX_CELL_IDS_H */
