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
};

/* Life of a cell. It only ever moves down this list. */
enum cell_state {
	CELL_BUILDING		= 0,	/* Slots may be filled */
	CELL_SEALED		= 1,	/* Immutable, nothing spawned yet */
	CELL_RUNNING		= 2,	/* Has, or had, its first task */
	CELL_DYING		= 3,	/* Killed, or its init exited */
	CELL_DEAD		= 4,	/* Nothing left. The status can be read */
};

#endif /* _UAPI_LINUX_CELL_H */
