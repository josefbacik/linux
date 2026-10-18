// SPDX-License-Identifier: GPL-2.0-only
/*
 * Embryo tasks: fsopen() for processes.
 *
 * clone3(CLONE_EMBRYO) returns a pidfd on a task that exists but has never run
 * a single instruction of user code, and never runs any of its creator's. The
 * creator sets it up with task_configure() and starts it, at which point it
 * execs. The creator does not fork.
 *
 * An embryo has no mm and an empty file table. What it is to reach, it is
 * given. It does inherit attributes of its creator, as any new task does, see
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
#include <uapi/linux/cell.h>
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

	char			*exec;
	struct embryo_strings	argv;
	struct embryo_strings	envp;

	int			result;
	struct completion	start;		/* starter -> embryo */
	struct completion	done;		/* embryo -> starter */
};

static void embryo_strings_free(struct embryo_strings *s)
{
	kvfree(s->block);
	kvfree(s->vec);
	s->block = NULL;
	s->vec = NULL;
}

static void embryo_put(struct embryo *e)
{
	if (!e || !refcount_dec_and_test(&e->ref))
		return;

	kfree(e->exec);
	embryo_strings_free(&e->argv);
	embryo_strings_free(&e->envp);
	kfree_rcu(e, rcu);
}

/* The task is done being an embryo, one way or the other. */
static void embryo_detach(struct embryo *e)
{
	WRITE_ONCE(current->embryo, NULL);
	embryo_put(e);
}

static int embryo_exec(struct embryo *e)
{
	static const char * const no_strings[] = { NULL };
	const char *argv0[] = { e->exec, NULL };

	return kernel_execve(e->exec, e->argv.vec ?: argv0,
			     e->envp.vec ?: no_strings);
}

static int embryo_main(void *arg)
{
	struct embryo *e = arg;
	int ret;

	/* CLONE_CLEAR_SIGHAND leaves what the creator ignores ignored. */
	flush_signal_handlers(current, 1);

	/* The creator's session, process group and terminal are not ours. */
	ksys_setsid();
	set_personality(PER_LINUX);

	ret = wait_for_completion_state(&e->start, TASK_KILLABLE | TASK_FREEZABLE |
					TASK_NOLOAD);
	if (ret) {
		/* A starter may have come along at the very same time. */
		e->result = -ESRCH;
		complete_all(&e->done);
		embryo_detach(e);
		do_group_exit(SIGKILL);
	}

	/* @started is set, so nobody changes anything any more. */
	ret = embryo_exec(e);
	/*
	 * A signal to the embryo is no signal to whoever started it. Whatever
	 * interrupted the exec, the embryo is about to be killed.
	 */
	if (ret && (fatal_signal_pending(current) || ret <= -ERESTARTSYS))
		ret = -ESRCH;
	e->result = ret;
	complete_all(&e->done);
	embryo_detach(e);
	if (ret)
		do_group_exit(SIGKILL);

	/* Off to user mode. */
	return 0;
}

/**
 * embryo_fork_prepare - get ready to create an embryo
 * @args: the arguments of a clone3() with CLONE_EMBRYO or CLONE_INTO_CELL
 *
 * Checks that the flags go together and turns @args into those of a task that
 * runs embryo_main(). For now CLONE_EMBRYO and CLONE_INTO_CELL need each other,
 * CLONE_PIDFD and CLONE_AUTOREAP.
 *
 * On success the cell is locked and embryo_fork_finish() must be called.
 *
 * Context: kernel_clone(), before copy_process().
 * Return: 0 or a negative error.
 */
int embryo_fork_prepare(struct kernel_clone_args *args)
{
	const u64 need = CLONE_EMBRYO | CLONE_INTO_CELL | CLONE_PIDFD | CLONE_AUTOREAP;
	const u64 allowed = need | CLONE_PIDFD_AUTOKILL | CLONE_NNP |
			    CLONE_CLEAR_SIGHAND;
	struct embryo *e;
	int ret;

	/* An embryo outside of a cell makes sense. It is not done yet. */
	if ((args->flags & need) != need)
		return -EINVAL;
	if (args->flags & ~allowed)
		return -EINVAL;
	if (args->stack || args->stack_size || args->tls || args->set_tid_size ||
	    args->child_tid || args->parent_tid || args->exit_signal)
		return -EINVAL;

	e = kzalloc_obj(struct embryo, GFP_KERNEL_ACCOUNT);
	if (!e)
		return -ENOMEM;
	refcount_set(&e->ref, 1);
	mutex_init(&e->lock);
	init_completion(&e->start);
	init_completion(&e->done);

	ret = cell_fork_prepare(args);
	if (ret) {
		kfree(e);
		return ret;
	}

	args->embryo = e;
	args->fn = embryo_main;
	args->fn_arg = e;
	args->name = "embryo";
	/*
	 * CLONE_VM only says "do not copy the mm": there is none, copy_mm()
	 * sees to that. The rest is what every task of a cell gets.
	 */
	args->flags |= CLONE_VM | CLONE_UNTRACED | CLONE_INTO_CGROUP | CLONE_NNP |
		       CLONE_CLEAR_SIGHAND;
	return 0;
}

/**
 * embryo_fork_finish - done creating an embryo, one way or the other
 * @args: what embryo_fork_prepare() succeeded on
 * @p:    what copy_process() returned, a task or an ERR_PTR()
 *
 * Context: kernel_clone(), before the new task is woken.
 */
void embryo_fork_finish(struct kernel_clone_args *args, struct task_struct *p)
{
	if (IS_ERR(p))
		embryo_put(args->embryo);
	else
		cell_task_spawned(args->cell);
	args->embryo = NULL;
	cell_fork_finish(args);
}

/**
 * embryo_pidfd_release - the pidfd clone3(CLONE_EMBRYO) returned was closed
 * @pid: what it was a pidfd of
 *
 * An embryo that nobody can start any more is killed. One that has been started
 * is left alone.
 *
 * Context: The ->release() of the file.
 */
void embryo_pidfd_release(struct pid *pid)
{
	struct task_struct *task;
	struct embryo *e;

	guard(rcu)();
	task = pid_task(pid, PIDTYPE_TGID);
	if (!task)
		return;
	e = READ_ONCE(task->embryo);
	if (e && !READ_ONCE(e->started))
		do_send_sig_info(SIGKILL, SEND_SIG_PRIV, task, PIDTYPE_TGID);
}
