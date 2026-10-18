// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cells: a task is born in a cell.
 */
#include <linux/cgroup.h>
#include <linux/fs_struct.h>
#include <linux/key.h>
#include <linux/pid_namespace.h>
#include <linux/sched/task.h>
#include <linux/security.h>
#include <uapi/linux/cell.h>
#include <uapi/linux/keyctl.h>

#include "internal.h"

/**
 * cell_fork_prepare - get ready to create a task in a cell
 * @args: the arguments of the clone. @args->cell_fd names the cell
 *
 * On success @args->cell is set and the cell is locked, until
 * cell_fork_finish(). A kill therefore either comes first, and this fails, or
 * waits and finds the new task in the budget.
 *
 * The pid namespace of the caller must be an ancestor of that of the cell, or
 * clone3() would have to return 0, which means something else.
 *
 * Return: 0, -EPERM if the caller is in a cell, whose "spawn" slot is empty,
 * -EINVAL if the cell is not sealed or out of the caller's sight,
 * -ESRCH if it is dying or dead, -EINTR on a fatal signal, or what is wrong
 * with the file descriptor.
 */
int cell_fork_prepare(struct kernel_clone_args *args)
{
	struct cell *cell;
	int ret;

	if (!cell_may_spawn())
		return -EPERM;

	CLASS(fd, f)(args->cell_fd);
	cell = cell_from_fd(&f);
	if (IS_ERR(cell))
		return PTR_ERR(cell);

	if (mutex_lock_killable(&cell->lock))
		return -EINTR;

	ret = cell->state == CELL_BUILDING ? -EINVAL : -ESRCH;
	if (cell->state != CELL_SEALED && cell->state != CELL_RUNNING)
		goto err;
	/*
	 * The caller must be able to see what it spawns, or clone3() would
	 * have to return 0, which means something else.
	 */
	ret = -EINVAL;
	if (!pidns_is_ancestor(cell->pid_ns, task_active_pid_ns(current)))
		goto err;

	args->cell = cell_get(cell);
	return 0;
err:
	mutex_unlock(&cell->lock);
	return ret;
}

/**
 * cell_fork_finish - done creating a task in a cell, one way or the other
 * @args: what cell_fork_prepare() succeeded on
 *
 * Unlocks the cell and drops the reference in @args->cell.
 */
void cell_fork_finish(struct kernel_clone_args *args)
{
	struct cell *cell = args->cell;

	args->cell = NULL;
	mutex_unlock(&cell->lock);
	cell_put(cell);
}

/**
 * cell_task_spawned - a task was created in a cell
 * @cell: the cell
 *
 * Context: Between cell_fork_prepare() and cell_fork_finish(), once
 * copy_process() has succeeded.
 */
void cell_task_spawned(struct cell *cell)
{
	lockdep_assert_held(&cell->lock);

	if (cell->state == CELL_SEALED)
		WRITE_ONCE(cell->state, CELL_RUNNING);
}

/**
 * cell_user_ns - the user namespace of a cell
 * @cell: a cell that has not been torn down
 *
 * Context: The caller holds the lock of the cell, as between
 * cell_fork_prepare() and cell_fork_finish().
 * Return: the user namespace. No reference is taken.
 */
struct user_namespace *cell_user_ns(struct cell *cell)
{
	return cell->user_ns;
}

/**
 * cell_nsproxy - the nsproxy every task of a cell shares
 * @cell: a sealed cell that has not been torn down
 *
 * Context: Between cell_fork_prepare() and cell_fork_finish().
 * Return: the nsproxy. No reference is taken.
 */
struct nsproxy *cell_nsproxy(struct cell *cell)
{
	return cell->nsproxy;
}

/**
 * cell_root - the root of the tree of a cell
 * @cell: a sealed cell that has not been torn down
 * @root: where to return it, with a reference
 *
 * Context: Between cell_fork_prepare() and cell_fork_finish().
 */
void cell_root(struct cell *cell, struct path *root)
{
	*root = cell->root;
	path_get(root);
}

/**
 * cell_budget - the cgroup that is the budget of a cell
 * @cell: a sealed cell that has not been torn down
 *
 * Context: Between cell_fork_prepare() and cell_fork_finish().
 * Return: the cgroup. No reference is taken.
 */
struct cgroup *cell_budget(struct cell *cell)
{
	return cell->budget;
}

/**
 * cell_copy_creds - make the credentials of a new task of a cell
 * @new:  a copy of the credentials of the spawner that nobody else can see yet
 * @cell: the cell
 *
 * Nothing that says who the spawner is survives: ids, groups, capabilities,
 * keyrings and user namespace become those of the cell. The LSM state does
 * survive, since a spawner must not shed a confinement by spawning.
 *
 * The task starts as the root of the cell, with every capability over the user
 * namespace of the cell but CAP_SETFCAP, which is gone from the bounding set
 * too. In a one-id cell it starts as the one id, with no capabilities and with
 * the groups of whoever made the cell.
 *
 * Context: Between cell_fork_prepare() and cell_fork_finish().
 * Return: 0 or a negative error, in which case the caller discards @new.
 */
int cell_copy_creds(struct cred *new, struct cell *cell)
{
	struct user_namespace *ns = cell->user_ns;
	struct group_info *groups;
	struct user_struct *user;
	kuid_t uid;
	kgid_t gid;

	if (cell->ids_count == 1) {
		uid = ns->owner;
		gid = ns->group;
	} else {
		uid = make_kuid(ns, 0);
		gid = make_kgid(ns, 0);
	}
	if (WARN_ON_ONCE(!uid_valid(uid) || !gid_valid(gid)))
		return -EINVAL;

	/*
	 * A one-id cell is its maker as far as files go, and that includes the
	 * groups that are there to deny it something. It cannot change them.
	 */
	if (cell->ids_count == 1)
		groups = get_group_info(cell->groups);
	else
		groups = groups_alloc(0);
	if (!groups)
		return -ENOMEM;
	user = alloc_uid(uid);
	if (!user) {
		put_group_info(groups);
		return -EAGAIN;
	}
	free_uid(new->user);
	new->user = user;

	new->uid = new->euid = new->suid = new->fsuid = uid;
	new->gid = new->egid = new->sgid = new->fsgid = gid;
	put_group_info(new->group_info);
	new->group_info = groups;

	userns_enter_cell(new, ns);

	/*
	 * Files impart no privilege. The task gets no_new_privs, so it cannot
	 * gain from a file. Without CAP_SETFCAP, for good, it cannot write a
	 * file that somebody else would gain from.
	 */
	cap_lower(new->cap_bset, CAP_SETFCAP);
	cap_lower(new->cap_permitted, CAP_SETFCAP);
	cap_lower(new->cap_effective, CAP_SETFCAP);
	if (cell->ids_count == 1) {
		/* It is whoever made the cell, and no more than that. */
		cap_clear(new->cap_permitted);
		cap_clear(new->cap_effective);
	}

#ifdef CONFIG_KEYS
	key_put(new->session_keyring);
	new->session_keyring = NULL;
	key_put(new->process_keyring);
	new->process_keyring = NULL;
	key_put(new->thread_keyring);
	new->thread_keyring = NULL;
	new->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
#endif

	return set_cred_ucounts(new);
}
