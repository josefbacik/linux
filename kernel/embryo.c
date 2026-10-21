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

static int embryo_pidfd_create(struct embryo *e, unsigned int flags)
{
	struct file *file;

	CLASS(get_unused_fd, fd)(O_CLOEXEC);
	if (fd < 0)
		return fd;
	file = pidfs_alloc_file(e->pid, flags | O_RDWR);
	if (IS_ERR(file))
		return PTR_ERR(file);

	file->private_data = e;
	fd_install(fd, file);
	return take_fd(fd);
}

/**
 * embryo_pidfd_open - pidfd_open() with PIDFD_EMPTY
 * @cfd:   the cell the task is going to be in
 * @flags: PIDFD_EMPTY, and PIDFD_NONBLOCK if wanted
 *
 * The struct pid is made here and gets no numbers before the task is started.
 * Its size goes by the pid namespace, which is why the cell has to be known by
 * now. It reserves nothing in there: whichever task is started first is the init
 * of the cell, and a pidfd that is left empty keeps no cell from dying.
 *
 * Return: the pidfd, which is always close-on-exec, -EPERM if the caller is in a
 * cell, -EOPNOTSUPP without a cell, what cell_fork_prepare() has to say about the
 * cell, or another negative error.
 */
int embryo_pidfd_open(int cfd, unsigned int flags)
{
	struct embryo *e;
	struct cell *cell;
	int ret;

	if (flags & ~(PIDFD_EMPTY | PIDFD_NONBLOCK))
		return -EINVAL;
	/* Whatever the file descriptor is. */
	if (!cell_may_spawn())
		return -EPERM;
	/* A task like this outside of a cell makes sense. It is not done yet. */
	if (cfd == -EBADF)
		return -EOPNOTSUPP;

	CLASS(fd, f)(cfd);
	if (fd_empty(f))
		return -EBADF;
	cell = cell_from_file(fd_file(f));
	if (!cell)
		return -EINVAL;

	e = kzalloc_obj(struct embryo, GFP_KERNEL_ACCOUNT);
	if (!e)
		return -ENOMEM;
	refcount_set(&e->ref, 1);
	mutex_init(&e->lock);
	init_completion(&e->done);

	ret = cell_fork_prepare(cell);
	if (ret) {
		kfree(e);
		return ret;
	}
	e->pid = alloc_pid_struct(cell_nsproxy(cell)->pid_ns_for_children);
	e->cell = cell_get(cell);
	cell_fork_finish(cell);

	ret = -ENOMEM;
	if (!e->pid)
		goto err_put;
	ret = pidfs_add_pid(e->pid);
	if (ret)
		goto err_pid;
	ret = embryo_pidfd_create(e, flags);
	if (ret >= 0)
		return ret;
err_pid:
	free_pid_struct(e->pid);
err_put:
	embryo_put(e);
	return ret;
}

/**
 * embryo_pidfd_is_empty - is there no task yet, rather than no task any more?
 * @file: a pidfd
 *
 * Return: true for what pidfd_open() returned for PIDFD_EMPTY, until there is a
 * task or it is known that there never will be.
 */
bool embryo_pidfd_is_empty(const struct file *file)
{
	const struct embryo *e = file->private_data;

	return (file->f_flags & PIDFD_EMPTY) && !READ_ONCE(e->settled);
}

/**
 * embryo_pidfd_release - what pidfd_open() returned for PIDFD_EMPTY was closed
 * @file: the pidfd
 *
 * A task that was started is left alone. If there never was one, neither is
 * there anything to kill.
 *
 * Context: The ->release() of the file.
 */
void embryo_pidfd_release(struct file *file)
{
	struct embryo *e = file->private_data;

	/* Otherwise free_pid() has dropped, or is going to drop, that reference. */
	if (!pid_has_numbers(e->pid))
		free_pid_struct(e->pid);
	embryo_put(e);
}
