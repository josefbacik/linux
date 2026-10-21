/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CELL_H
#define _LINUX_CELL_H

/*
 * Cells, see Documentation/userspace-api/cells.rst.
 *
 * Each group of declarations below comes with its own stubs for a kernel
 * without CONFIG_CELLS.
 */

#include <linux/cell_ids.h>
#include <linux/cred.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>

struct cell;
struct cgroup;
struct file;
struct kernel_clone_args;
struct ns_common;
struct nsproxy;
struct path;
struct pid;
struct task_struct;

/* Who is in which cell. */
#ifdef CONFIG_CELLS

/**
 * userns_cell - the cell a user namespace belongs to
 * @ns: a user namespace
 *
 * Return: the cell, or NULL if @ns is a legacy user namespace. No reference is
 * taken: @ns holds one for as long as it lives.
 */
static inline struct cell *userns_cell(const struct user_namespace *ns)
{
	return ns->cell;
}

/**
 * cred_cell - the cell a credential belongs to
 * @cred: a credential
 *
 * The cell is reached through the user namespace of the credential, so it
 * follows override_creds() and file->f_cred without any help.
 *
 * Return: the cell, or NULL for the host. No reference is taken: @cred pins its
 * user namespace, which pins the cell.
 */
static inline struct cell *cred_cell(const struct cred *cred)
{
	return userns_cell(cred->user_ns);
}

/**
 * current_cell - the cell the caller acts in
 *
 * Goes by the subjective credentials, so a caller that has overridden its
 * credentials acts in the cell of those.
 *
 * Return: the cell, or NULL for the host.
 */
static inline struct cell *current_cell(void)
{
	return cred_cell(current_cred());
}

/**
 * cell_may_spawn - may the caller make cells and start tasks in them?
 *
 * This is the "spawn" slot of the cell the caller acts in. There is nothing to
 * fill it with yet, so it is always empty, and the host holds everything. That
 * no cellfd gets into a cell is not what this rests on.
 *
 * Return: true if it may.
 */
static inline bool cell_may_spawn(void)
{
	return !current_cell();
}

/**
 * task_cell - the cell a task is in
 * @task: a task
 *
 * A task is born in a cell and never changes cell.
 *
 * Context: The caller holds rcu_read_lock(), or otherwise keeps the objective
 * credentials of @task from going away.
 * Return: the cell, or NULL for the host.
 */
static inline struct cell *task_cell(const struct task_struct *task)
{
	return cred_cell(__task_cred(task));
}

/**
 * cell_same - do two credentials belong to the same cell?
 * @a: a credential
 * @b: another
 *
 * Across cells an equal uid means nothing: a one-id cell runs on the kuid of
 * whoever made it. A check that lets one task act on another because their uids
 * are equal asks this as well, and otherwise falls back to whatever capability
 * check it has.
 *
 * Return: true if both belong to the same cell, or both to the host.
 */
static inline bool cell_same(const struct cred *a, const struct cred *b)
{
	return cred_cell(a) == cred_cell(b);
}

u64 cell_id(const struct cell *cell);

/**
 * cred_cell_id - the id of the cell a credential belongs to
 * @cred: a credential
 *
 * For where a cell has to be remembered beyond the life of anything that pins
 * it. Ids are never reused, so they can be compared at any later time.
 *
 * Return: the id of the cell, or 0 for the host.
 */
static inline u64 cred_cell_id(const struct cred *cred)
{
	struct cell *cell = cred_cell(cred);

	return cell ? cell_id(cell) : 0;
}

/**
 * current_cell_id - the id of the cell the caller acts in
 *
 * Return: the id of the cell, or 0 for the host.
 */
static inline u64 current_cell_id(void)
{
	return cred_cell_id(current_cred());
}

struct cell *cell_get(struct cell *cell);
void cell_put(struct cell *cell);

#else

static inline struct cell *userns_cell(const struct user_namespace *ns) { return NULL; }
static inline struct cell *cred_cell(const struct cred *cred) { return NULL; }
static inline struct cell *current_cell(void) { return NULL; }
static inline bool cell_may_spawn(void) { return true; }
static inline struct cell *task_cell(const struct task_struct *t) { return NULL; }
static inline bool cell_same(const struct cred *a, const struct cred *b) { return true; }
static inline u64 cred_cell_id(const struct cred *cred) { return 0; }
static inline u64 current_cell_id(void) { return 0; }
static inline void cell_put(struct cell *cell) { }

#endif

/* The id block allocator. */
#ifdef CONFIG_CELLS
void cell_block_release(u32 block);
#else
static inline void cell_block_release(u32 block) { }
#endif

/* The cellfd. */
#ifdef CONFIG_CELLS
extern const struct file_operations cell_file_operations;
struct file *cellfs_alloc_file(struct cell *cell);
struct cell *cell_from_file(const struct file *file);
struct dentry **cell_stashed(struct cell *cell);
#endif

/* A task is born in a cell. */
#ifdef CONFIG_CELLS
int cell_fork_prepare(struct cell *cell);
void cell_fork_finish(struct cell *cell);
void cell_task_spawned(struct cell *cell);
int cell_copy_creds(struct cred *new, struct cell *cell);
struct user_namespace *cell_user_ns(struct cell *cell);
struct nsproxy *cell_nsproxy(struct cell *cell);
void cell_root(struct cell *cell, struct path *root);
struct cgroup *cell_budget(struct cell *cell);
#else
static inline int cell_copy_creds(struct cred *n, struct cell *c) { return -EINVAL; }
static inline struct user_namespace *cell_user_ns(struct cell *cell) { return NULL; }
static inline struct nsproxy *cell_nsproxy(struct cell *cell) { return NULL; }
static inline void cell_root(struct cell *cell, struct path *root) { }
static inline struct cgroup *cell_budget(struct cell *cell) { return NULL; }
#endif

/* Embryo tasks. */
#ifdef CONFIG_CELLS

/**
 * task_is_embryo - is a task still on its way to its first exec?
 * @task: a task
 *
 * Return: true from the time PIDFD_CMD_START made @task until its exec has
 * succeeded or it is on its way out.
 */
static inline bool task_is_embryo(const struct task_struct *task)
{
	return READ_ONCE(task->embryo);
}

void embryo_fork_finish(struct kernel_clone_args *args, struct task_struct *p);

#else

static inline bool task_is_embryo(const struct task_struct *task) { return false; }
static inline void embryo_fork_finish(struct kernel_clone_args *a, struct task_struct *p) { }

#endif

#endif /* _LINUX_CELL_H */
