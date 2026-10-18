// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cells: a container as one kernel object.
 *
 * A task is born in a cell and never leaves it. There is no way to enter one.
 * A cell is built from the outside: the builder fills named slots from file
 * descriptors it holds, seals the cell, and spawns the first task into it.
 * Holding the cellfd is the authority to do all of that.
 *
 * Life:  BUILDING -> SEALED -> RUNNING -> DYING -> DEAD
 *
 * References. The cell owns a reference on its user namespace until it is torn
 * down. The user namespace owns a reference on the cell until it is freed, so
 * that current_cell() can be followed from any credential. Teardown breaks the
 * cycle, and every cell is torn down: by a kill, by the exit of its first task,
 * or by the last cellfd going away before anything ran.
 *
 * Locking. cell->lock serialises configuration, sealing, spawning and killing.
 * It is held across copy_process(), which is what closes a kill against a spawn
 * in flight. It nests outside cgroup_mutex and namespace_sem.
 */
#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/poll.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <net/net_namespace.h>
#include <uapi/linux/cell.h>

#include "internal.h"

static atomic64_t cell_next_id = ATOMIC64_INIT(0);

/**
 * cell_id - the id of a cell
 * @cell: a cell
 *
 * Return: the id. It is never 0, which stands for the host, and never reused.
 */
u64 cell_id(const struct cell *cell)
{
	return cell->id;
}

/**
 * cell_stashed - where cellfs keeps the dentry of a cell
 * @cell: a cell
 *
 * Return: the location to hand to path_from_stashed().
 */
struct dentry **cell_stashed(struct cell *cell)
{
	return &cell->stashed;
}

/**
 * cell_get - take a reference on a cell
 * @cell: a cell the caller already holds a reference on
 *
 * A reference keeps the memory of the cell around and nothing else. It neither
 * keeps the cell alive nor is it a handle on it.
 *
 * Return: @cell.
 */
struct cell *cell_get(struct cell *cell)
{
	refcount_inc(&cell->ref);
	return cell;
}

/**
 * cell_put - drop a reference on a cell
 * @cell: a cell, or NULL
 *
 * Context: Process context. The cell is freed after a grace period.
 */
void cell_put(struct cell *cell)
{
	if (!cell || !refcount_dec_and_test(&cell->ref))
		return;
	if (cell->groups)
		put_group_info(cell->groups);
	kfree_rcu(cell, rcu);
}

/*
 * Teardown. Drops every reference the cell holds and only then says DEAD. What
 * that sets off, the release of mounts, of the network namespace and of the
 * block of ids, completes on its own time.
 */
static void cell_teardown(struct cell *cell)
{
	struct cgroup *budget = cell->budget;

	lockdep_assert_held(&cell->lock);

	/* cell_may_migrate() looks at this under nothing but RCU. */
	WRITE_ONCE(cell->budget, NULL);

	if (cell->nsproxy)
		put_nsproxy(cell->nsproxy);
	cell->nsproxy = NULL;
	path_put(&cell->root);
	memset(&cell->root, 0, sizeof(cell->root));
	if (cell->mnt_ns)
		put_mnt_ns(cell->mnt_ns);
	cell->mnt_ns = NULL;
	if (cell->pid_ns)
		put_pid_ns(cell->pid_ns);
	cell->pid_ns = NULL;
	if (cell->net)
		put_net(cell->net);
	cell->net = NULL;
	if (budget) {
		/*
		 * The ids of the cell were only lent, so nothing may go on
		 * being owned by them. If that cannot be had, the block is
		 * never handed out again.
		 */
		if (cgroup_cell_budget_put(budget, cell->sealed, cell->budget_uid,
					   cell->budget_gid))
			userns_retire_cell_block(cell->user_ns);
	}
	put_user_ns(cell->user_ns);
	cell->user_ns = NULL;

	/* Pairs with the acquire of whoever goes on to read the status. */
	smp_store_release(&cell->state, CELL_DEAD);
	wake_up_all(&cell->wait);
}

static void cell_kill_locked(struct cell *cell)
{
	lockdep_assert_held(&cell->lock);

	switch (cell->state) {
	case CELL_BUILDING:
	case CELL_SEALED:
		/* Nothing ever ran. */
		cell->exit_status = SIGKILL;
		cell_teardown(cell);
		break;
	case CELL_RUNNING:
		WRITE_ONCE(cell->state, CELL_DYING);
		fallthrough;
	case CELL_DYING:
		/* The exit of the cell's init finishes the job. */
		cgroup_cell_kill(cell->budget);
		break;
	case CELL_DEAD:
		break;
	}
}

static void cell_kill(struct cell *cell)
{
	guard(mutex)(&cell->lock);
	cell_kill_locked(cell);
}

/* The last cellfd is gone, and there is no way to get another. */
static void cell_kill_workfn(struct work_struct *work)
{
	struct cell *cell = container_of(work, struct cell, kill_work);

	cell_kill(cell);
	cell_put(cell);
}

static void cell_exit_workfn(struct work_struct *work)
{
	struct cell *cell = container_of(to_delayed_work(work), struct cell,
					 exit_work);

	scoped_guard(mutex, &cell->lock) {
		if (cell->state == CELL_DEAD)
			break;
		WRITE_ONCE(cell->state, CELL_DYING);
		/*
		 * DEAD means gone. zap_pid_ns_processes() has reaped everything
		 * else in the pid namespace, but the init itself is still on
		 * its way out. It populates the budget until it is off the cpu
		 * for good. Come back until then.
		 */
		if (cgroup_cell_kill(cell->budget)) {
			queue_delayed_work(system_dfl_wq, &cell->exit_work,
					   max(HZ / 100, 1));
			return;
		}
		cell_teardown(cell);
	}
	cell_put(cell);
}

/**
 * cell_init_exited - the init of the pid namespace of a cell is gone
 * @cell: the cell
 * @tsk:  the last thread of that init, which is the caller
 *
 * With its init everything else in the pid namespace is gone, and so the cell.
 * This notes the exit status and owes the teardown to a work item.
 *
 * Context: The exit path of @tsk, after zap_pid_ns_processes(), with no locks
 * held. The cell has not been torn down, since only this sets that off once a
 * cell has run anything.
 */
void cell_init_exited(struct cell *cell, struct task_struct *tsk)
{
	cell->exit_status = (tsk->signal->flags & SIGNAL_GROUP_EXIT) ?
			    tsk->signal->group_exit_code :
			    tsk->group_leader->exit_code;
	cell_get(cell);
	if (!queue_delayed_work(system_dfl_wq, &cell->exit_work, 0))
		cell_put(cell);
}

/* The cellfd. */

static int cell_file_open(struct inode *inode, struct file *file)
{
	/*
	 * A handle is handed out, by cellfs_alloc_file(), and passed on. It is
	 * not opened again through /proc/<pid>/fd: the inode is immutable, so
	 * may_open() refuses that for writing, and this refuses the rest.
	 */
	if (!(file->f_mode & FMODE_WRITE))
		return -ENXIO;

	return 0;
}

static int cell_file_release(struct inode *inode, struct file *file)
{
	struct cell *cell = inode->i_private;

	/*
	 * A cell has the one file that cell_create() made, however many file
	 * descriptors refer to it. Nobody can reach the cell any more, and there
	 * is no way to get another handle, so it goes: a cell lives for as long
	 * as somebody holds it. The last fput() may come from anywhere, so only
	 * owe the kill here.
	 */
	cell_get(cell);
	if (!queue_work(system_dfl_wq, &cell->kill_work))
		cell_put(cell);
	return 0;
}

static bool cell_is_dead(struct cell *cell)
{
	/* Pairs with the release in cell_teardown(): the status is there. */
	return smp_load_acquire(&cell->state) == CELL_DEAD;
}

static __poll_t cell_file_poll(struct file *file, poll_table *pts)
{
	struct cell *cell = cell_from_file(file);

	poll_wait(file, &cell->wait, pts);
	if (cell_is_dead(cell))
		return EPOLLIN | EPOLLRDNORM;
	return 0;
}

/* Reads the wait status of the cell's first task. Repeatable. */
static ssize_t cell_file_read(struct file *file, char __user *buf, size_t count,
			      loff_t *ppos)
{
	struct cell *cell = cell_from_file(file);
	__s32 status;
	int ret;

	if (count < sizeof(status))
		return -EINVAL;

	if (!cell_is_dead(cell)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(cell->wait, cell_is_dead(cell));
		if (ret)
			return ret;
	}

	status = cell->exit_status;
	if (copy_to_user(buf, &status, sizeof(status)))
		return -EFAULT;
	return sizeof(status);
}

const struct file_operations cell_file_operations = {
	.open		= cell_file_open,
	.release	= cell_file_release,
	.poll		= cell_file_poll,
	.read		= cell_file_read,
	.llseek		= noop_llseek,
};

/**
 * sys_cell_create - make a new, empty cell
 * @parent: CELL_SELF
 * @flags:  none yet, must be 0
 *
 * The cell holds nothing, is in state CELL_BUILDING and can already be killed.
 * It takes no privilege beyond what making a user namespace takes. A task of a
 * cell cannot make one.
 *
 * Return: a cellfd, which is always close-on-exec, or a negative error.
 */
SYSCALL_DEFINE2(cell_create, int, parent, unsigned int, flags)
{
	struct cell *cell;
	struct cred *cred;
	int ret;

	if (flags)
		return -EINVAL;
	if (parent != CELL_SELF)
		return -EINVAL;
	if (!cell_may_spawn())
		return -EPERM;

	cell = kzalloc_obj(struct cell, GFP_KERNEL_ACCOUNT);
	if (!cell)
		return -ENOMEM;

	refcount_set(&cell->ref, 1);
	cell->id = atomic64_inc_return(&cell_next_id);
	mutex_init(&cell->lock);
	init_waitqueue_head(&cell->wait);
	INIT_WORK(&cell->kill_work, cell_kill_workfn);
	INIT_DELAYED_WORK(&cell->exit_work, cell_exit_workfn);
	strscpy(cell->hostname, "(none)");

	/* The scratch credential is only here to carry the new namespace. */
	cred = prepare_creds();
	if (!cred) {
		kfree(cell);
		return -ENOMEM;
	}
	ret = create_cell_user_ns(cred, cell);
	if (ret) {
		abort_creds(cred);
		kfree(cell);
		return ret;
	}
	cell->user_ns = get_user_ns(cred->user_ns);
	cell->groups = get_group_info(cred->group_info);
	abort_creds(cred);

	ret = FD_ADD(O_CLOEXEC, cellfs_alloc_file(cell));
	if (ret < 0)
		cell_kill(cell);
	cell_put(cell);
	return ret;
}

/**
 * sys_cell_kill - kill a cell and everything in it
 * @cfd:   the cell, in whatever state
 * @flags: none yet, must be 0
 *
 * Kills every task in the budget. A cell that has run nothing yet is torn down
 * on the spot. For one that has, that is for the exit of its init to set off, so
 * this does not wait: the cellfd polls readable once the cell is dead. Killing a
 * cell that is dying or dead already changes nothing.
 *
 * Return: 0, -EINVAL for a flag or a file that is no cellfd, -EBADF.
 */
SYSCALL_DEFINE2(cell_kill, int, cfd, unsigned int, flags)
{
	struct cell *cell;

	if (flags)
		return -EINVAL;

	CLASS(fd, f)(cfd);
	cell = cell_from_fd(&f);
	if (IS_ERR(cell))
		return PTR_ERR(cell);

	cell_kill(cell);
	return 0;
}

#define CELL_INFO_SUPPORTED	(CELL_INFO_ID | CELL_INFO_STATE | CELL_INFO_EXIT | \
				 CELL_INFO_BUDGET | CELL_INFO_IDS)

/**
 * sys_cell_info - read from a cell
 * @cfd:   a cellfd, or CELL_SELF, which tells a task the id of its own cell
 * @uinfo: where to return it. Only @uinfo->mask is read
 * @usize: the size of *@uinfo as the caller knows it
 * @flags: none yet, must be 0
 *
 * Fills in what @uinfo->mask asks for and the kernel has, and says in the mask
 * what that was. @uinfo->supported_mask is everything this kernel knows of.
 *
 * Return: 0 or a negative error.
 */
SYSCALL_DEFINE4(cell_info, int, cfd, struct cell_info __user *, uinfo,
		size_t, usize, unsigned int, flags)
{
	struct cell_info info = {};
	struct cell *cell;
	u64 want;

	BUILD_BUG_ON(sizeof(struct cell_info) != CELL_INFO_SIZE_VER0);

	if (flags)
		return -EINVAL;
	if (usize < CELL_INFO_SIZE_VER0)
		return -EINVAL;
	/* Only the mask goes in. The rest of the struct is the kernel's to fill. */
	if (get_user(want, &uinfo->mask))
		return -EFAULT;
	info.supported_mask = CELL_INFO_SUPPORTED;

	if (cfd == CELL_SELF) {
		/* A name, and nothing that a handle would be needed for. */
		info.id = current_cell_id();
		info.mask = want & CELL_INFO_ID;
		return copy_struct_to_user(uinfo, usize, &info, sizeof(info), NULL);
	}

	CLASS(fd, f)(cfd);
	cell = cell_from_fd(&f);
	if (IS_ERR(cell))
		return PTR_ERR(cell);

	scoped_guard(mutex, &cell->lock) {
		if (want & CELL_INFO_ID) {
			info.id = cell->id;
			/* Cells do not nest yet. */
			info.parent_id = 0;
			info.mask |= CELL_INFO_ID;
		}
		if (want & CELL_INFO_STATE) {
			info.state = cell->state;
			/* There are none yet. */
			info.flags = 0;
			info.mask |= CELL_INFO_STATE;
		}
		if ((want & CELL_INFO_EXIT) && cell->state == CELL_DEAD) {
			info.exit_status = cell->exit_status;
			info.mask |= CELL_INFO_EXIT;
		}
		if ((want & CELL_INFO_BUDGET) && cell->budget_id) {
			info.budget_cgroupid = cell->budget_id;
			info.mask |= CELL_INFO_BUDGET;
		}
		if ((want & CELL_INFO_IDS) && cell->ids_count) {
			info.ids_count = cell->ids_count;
			info.mask |= CELL_INFO_IDS;
		}
	}
	return copy_struct_to_user(uinfo, usize, &info, sizeof(info), NULL);
}
