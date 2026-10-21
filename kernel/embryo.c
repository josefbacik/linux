// SPDX-License-Identifier: GPL-2.0-only
/*
 * Empty pidfds: fsopen() for processes.
 *
 * pidfd_open() with PIDFD_EMPTY returns a pidfd that no task is attached to yet.
 * It is a pidfd like any other, on a struct pid that has no numbers, so whatever
 * it is passed to finds no task. Whoever has it says with pidfd_configure() what
 * the task is to be like and starts it. Only then is there a task, which never
 * runs a single instruction of its creator's and execs. The creator does not
 * fork.
 *
 * The task is an embryo until its exec has succeeded. It has no mm and an empty
 * file table. What it is to reach, it is given. It does inherit attributes of
 * whoever started it, as any new task does, see
 * Documentation/userspace-api/cells.rst.
 *
 * It takes the shape of a usermode helper: a task with a kernel function to
 * run, that returns to user mode once kernel_execve() has succeeded.
 */
#include <linux/binfmts.h>
#include <linux/cell.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/io_uring.h>
#include <linux/personality.h>
#include <linux/nsproxy.h>
#include <linux/pid.h>
#include <linux/pidfs.h>
#include <linux/proc_fs.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/user.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/user_namespace.h>
#include <net/af_unix.h>
#include <uapi/linux/pidfd.h>

struct embryo_strings {
	char		*block;		/* NUL terminated strings, back to back */
	const char	**vec;		/* NULL terminated, points into @block */
};

struct embryo {
	struct rcu_head		rcu;
	refcount_t		ref;
	struct mutex		lock;		/* everything down to @result */
	bool			started;
	bool			settled;	/* there is a task, or never will be */

	char			*exec;
	struct embryo_strings	argv;
	struct embryo_strings	envp;

	struct pid		*pid;		/* the reference alloc_pid_struct() returned */
	struct cell		*cell;		/* where the task is going to be */

	int			result;
	struct completion	done;		/* embryo -> starter */
};

static void embryo_strings_free(struct embryo_strings *s)
{
	kvfree(s->block);
	kvfree(s->vec);
	s->block = NULL;
	s->vec = NULL;
}

/*
 * What was configured has been used, or never will be. The pidfd may be around
 * for long, and must not keep the other end of a pipe from seeing the last
 * writer go.
 */
static void embryo_drop_config(struct embryo *e)
{
	kfree(e->exec);
	e->exec = NULL;
	embryo_strings_free(&e->argv);
	embryo_strings_free(&e->envp);
}

static void embryo_put(struct embryo *e)
{
	if (!e || !refcount_dec_and_test(&e->ref))
		return;

	embryo_drop_config(e);
	cell_put(e->cell);
	kfree_rcu(e, rcu);
}

/**
 * embryo_fork_finish - done creating an embryo, one way or the other
 * @args: the arguments of the clone, with @args->embryo set
 * @p:    what copy_process() returned, a task or an ERR_PTR()
 *
 * Unlocks the cell, which embryo_start() had locked.
 *
 * Context: kernel_clone(), before the new task is woken.
 */
void embryo_fork_finish(struct kernel_clone_args *args, struct task_struct *p)
{
	struct embryo *e = args->embryo;

	if (!IS_ERR(p))
		cell_task_spawned(args->cell);
	cell_fork_finish(args->cell);

	/* From here on the pidfd polls like any other. */
	WRITE_ONCE(e->settled, true);
	if (IS_ERR(p)) {
		wake_up_all(&e->pid->wait_pidfd);
		/* The reference that was to be the task's. */
		embryo_put(e);
	}
}
