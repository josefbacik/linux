/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_CELL_H
#define _UAPI_LINUX_CELL_H

#include <linux/types.h>

/*
 * A cell is a container: one kernel object that a task is born into and never
 * leaves. It is built from the outside, by filling named slots from file
 * descriptors the builder holds, and then sealed.
 */

/* cell_create(): @parent is CELL_SELF, see <linux/fcntl.h>. */

/* cell_configure(): @cmd. Data only ever goes in. */
enum cell_configure_cmd {
	CELL_SET_FLAG		= 0,	/* Set the flag named by @key. There are none yet */
	CELL_SET_STRING		= 1,	/* Set @key to the string in @value */
	CELL_SET_BINARY		= 2,	/* Set @key to the @aux bytes at @value */
	CELL_SET_FD		= 3,	/* Fill the slot named by @key from fd @aux */
	CELL_CMD_SEAL		= 4,	/* Validate everything and seal */
	CELL_CMD_KILL		= 5,	/* Destroy the cell and everything in it */
};

/* Life of a cell. It only ever moves down this list. */
enum cell_state {
	CELL_BUILDING		= 0,	/* Slots may be filled */
	CELL_SEALED		= 1,	/* Immutable, nothing spawned yet */
	CELL_RUNNING		= 2,	/* Has, or had, its first task */
	CELL_DYING		= 3,	/* Killed, or its init exited */
	CELL_DEAD		= 4,	/* Nothing left. The status can be read */
};

/* cell_info(): bits for @mask. */
#define CELL_INFO_ID		(1ULL << 0)	/* id, parent_id */
#define CELL_INFO_STATE		(1ULL << 1)	/* state, flags */
#define CELL_INFO_EXIT		(1ULL << 2)	/* exit_status, once CELL_DEAD */
#define CELL_INFO_BUDGET	(1ULL << 3)	/* budget_cgroupid */
#define CELL_INFO_IDS		(1ULL << 4)	/* ids_count */

struct cell_info {
	__u64 mask;		/* in: what is wanted. out: what was filled in */
	__u64 supported_mask;	/* out: everything this kernel can fill in */
	__u64 id;		/* never reused */
	__u64 parent_id;	/* 0: the host */
	__u32 state;		/* enum cell_state */
	__u32 flags;		/* none yet */
	__s32 exit_status;	/* as wait(2) reports it, of the cell's first task */
	__u32 ids_count;	/* how many uids and gids the cell has */
	__u64 budget_cgroupid;
};

#define CELL_INFO_SIZE_VER0	56

/* cell_open(): @what. */
enum cell_open_what {
	CELL_OPEN_SLOT		= 0,	/* An fd on the object in the slot named by @key */
};

/* task_configure(): @cmd. */
enum task_configure_cmd {
	TASK_SET_STRING		= 0,	/* Set @key to the string in @value */
	TASK_SET_BINARY		= 1,	/* Set @key to the @aux bytes at @value */
	TASK_SET_FD		= 2,	/* The file to have at number @key, from fd @aux */
	TASK_CMD_START		= 3,	/* Apply everything and exec */
};

#endif /* _UAPI_LINUX_CELL_H */
