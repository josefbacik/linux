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

#define EMBRYO_KEY_MAX		32
#define EMBRYO_MAX_FDS		256
#define EMBRYO_MAX_FD		1024
#define EMBRYO_MAX_STRINGS	4096
#define EMBRYO_MAX_BLOCK	(256 * 1024)

struct embryo_fd {
	unsigned int	fd;
	struct file	*file;
};

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
	struct embryo_fd	fds[EMBRYO_MAX_FDS];
	unsigned int		nr_fds;

	bool			have_cred;
	kuid_t			uid;
	kgid_t			gid;
	struct group_info	*groups;

	struct pid		*pid;		/* the reference alloc_pid_struct() returned */
	struct cell		*cell;		/* where the task is going to be */
	struct user_namespace	*user_ns;	/* likewise */

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

static void embryo_put_fds(struct embryo *e)
{
	unsigned int i;

	for (i = 0; i < e->nr_fds; i++)
		fput(e->fds[i].file);
	e->nr_fds = 0;
}

/* In the context of the embryo, whose file table is empty. */
static int embryo_install_fds(struct embryo *e)
{
	unsigned int i;
	int ret;

	for (i = 0; i < e->nr_fds; i++) {
		struct file *file = e->fds[i].file;

		ret = security_file_receive(file);
		if (ret)
			return ret;
		ret = replace_fd(e->fds[i].fd, file, 0);
		if (ret < 0)
			return ret;
	}
	return 0;
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
	embryo_put_fds(e);
	if (e->groups)
		put_group_info(e->groups);
	e->groups = NULL;
}

static void embryo_put(struct embryo *e)
{
	if (!e || !refcount_dec_and_test(&e->ref))
		return;

	embryo_drop_config(e);
	put_user_ns(e->user_ns);
	cell_put(e->cell);
	kfree_rcu(e, rcu);
}

/* The task is done being an embryo, one way or the other. */
static void embryo_detach(struct embryo *e)
{
	WRITE_ONCE(current->embryo, NULL);
	embryo_put(e);
}

static int embryo_apply_cred(struct embryo *e)
{
	const struct cred *old = current_cred();
	struct user_struct *user;
	struct cred *new;
	int ret;

	if (!e->have_cred)
		return 0;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	new->uid = new->euid = new->suid = new->fsuid = e->uid;
	new->gid = new->egid = new->sgid = new->fsgid = e->gid;
	if (e->groups)
		set_groups(new, e->groups);

	ret = -EAGAIN;
	user = alloc_uid(e->uid);
	if (!user)
		goto err;
	free_uid(new->user);
	new->user = user;

	/* Leaving uid 0 behind costs the capabilities, as setresuid() would. */
	ret = security_task_fix_setuid(new, old, LSM_SETID_RES);
	if (ret)
		goto err;
	ret = security_task_fix_setgid(new, old, LSM_SETID_RES);
	if (ret)
		goto err;
	ret = security_task_fix_setgroups(new, old);
	if (ret)
		goto err;
	ret = set_cred_ucounts(new);
	if (ret)
		goto err;
	return commit_creds(new);

err:
	abort_creds(new);
	return ret;
}

static int embryo_exec(struct embryo *e)
{
	static const char * const no_strings[] = { NULL };
	const char *argv0[] = { e->exec, NULL };
	int ret;

	ret = embryo_install_fds(e);
	if (ret)
		return ret;
	ret = embryo_apply_cred(e);
	if (ret)
		return ret;

	return kernel_execve(e->exec, e->argv.vec ?: argv0,
			     e->envp.vec ?: no_strings);
}

static int embryo_main(void *arg)
{
	struct embryo *e = arg;
	int ret;

	/* CLONE_CLEAR_SIGHAND leaves what the starter ignores ignored. */
	flush_signal_handlers(current, 1);

	/* The starter's session, process group and terminal are not ours. */
	ksys_setsid();
	set_personality(PER_LINUX);

	/* @started is set, so nobody changes anything any more. */
	ret = embryo_exec(e);
	embryo_drop_config(e);
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
	e->user_ns = get_user_ns(cell_user_ns(cell));
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

static struct embryo *embryo_from_file(struct file *file)
{
	struct pid *pid;

	pid = pidfd_pid(file);
	if (IS_ERR(pid))
		return ERR_CAST(pid);
	/* Only the file pidfd_open() returned will do. Nothing else ever has this. */
	if (!(file->f_flags & PIDFD_EMPTY))
		return ERR_PTR(-EPERM);
	return file->private_data;
}

static int embryo_set_strings(struct embryo_strings *s, const void __user *ublock,
			      size_t len)
{
	struct embryo_strings new = {};
	unsigned int nr = 0, i;
	size_t off;

	if (!len || len > EMBRYO_MAX_BLOCK)
		return -E2BIG;

	new.block = vmemdup_user(ublock, len);
	if (IS_ERR(new.block))
		return PTR_ERR(new.block);
	if (new.block[len - 1]) {
		kvfree(new.block);
		return -EINVAL;
	}

	for (off = 0; off < len; off += strlen(new.block + off) + 1)
		nr++;
	if (nr > EMBRYO_MAX_STRINGS) {
		kvfree(new.block);
		return -E2BIG;
	}

	new.vec = kvmalloc_array(nr + 1, sizeof(*new.vec), GFP_KERNEL_ACCOUNT);
	if (!new.vec) {
		kvfree(new.block);
		return -ENOMEM;
	}
	for (off = 0, i = 0; off < len; off += strlen(new.block + off) + 1)
		new.vec[i++] = new.block + off;
	new.vec[i] = NULL;

	embryo_strings_free(s);
	*s = new;
	return 0;
}

static int embryo_set_cred(struct embryo *e, const void __user *uvalue, size_t len)
{
	struct group_info *groups = NULL;
	struct pidfd_cred tc;
	kuid_t uid;
	kgid_t gid;
	u32 i;

	if (len != sizeof(tc))
		return -EINVAL;
	if (copy_from_user(&tc, uvalue, sizeof(tc)))
		return -EFAULT;
	if (tc.__spare || tc.ngroups > NGROUPS_MAX)
		return -EINVAL;

	/* The ids are the cell's own. One it does not have cannot be named. */
	uid = make_kuid(e->user_ns, tc.uid);
	gid = make_kgid(e->user_ns, tc.gid);
	if (!uid_valid(uid) || !gid_valid(gid))
		return -EINVAL;

	if (tc.ngroups) {
		const u32 __user *ugroups = u64_to_user_ptr(tc.groups);

		if (!userns_may_setgroups(e->user_ns))
			return -EPERM;
		groups = groups_alloc(tc.ngroups);
		if (!groups)
			return -ENOMEM;
		for (i = 0; i < tc.ngroups; i++) {
			u32 g;

			if (get_user(g, ugroups + i)) {
				put_group_info(groups);
				return -EFAULT;
			}
			groups->gid[i] = make_kgid(e->user_ns, g);
			if (!gid_valid(groups->gid[i])) {
				put_group_info(groups);
				return -EINVAL;
			}
		}
		groups_sort(groups);
	}

	if (e->groups)
		put_group_info(e->groups);
	e->groups = groups;
	e->uid = uid;
	e->gid = gid;
	e->have_cred = true;
	return 0;
}

/*
 * The file table of the new task is exactly what is put here. After this
 * nothing crosses the boundary of the cell any more, so this is where it is
 * decided what may.
 */
static int embryo_set_fd(struct embryo *e, const char *key, struct file *file)
{
	unsigned int fd, i;
	int ret;

	ret = kstrtouint(key, 10, &fd);
	if (ret)
		return -EINVAL;
	if (fd >= EMBRYO_MAX_FD)
		return -EBADF;

	/* Handles on what is outside, or means to get at it. */
	if (io_is_uring_fops(file) || cell_from_file(file) || proc_ns_file(file))
		return -EPERM;
	if (!IS_ERR(pidfd_pid(file)) && (file->f_flags & PIDFD_EMPTY))
		return -EPERM;

	for (i = 0; i < e->nr_fds; i++) {
		if (e->fds[i].fd == fd) {
			fput(e->fds[i].file);
			e->fds[i].file = get_file(file);
			return 0;
		}
	}
	if (e->nr_fds == EMBRYO_MAX_FDS)
		return -EMFILE;
	e->fds[e->nr_fds].fd = fd;
	e->fds[e->nr_fds].file = get_file(file);
	e->nr_fds++;
	return 0;
}

static int embryo_start(struct embryo *e)
{
	struct kernel_clone_args args = {
		/*
		 * CLONE_VM only says "do not copy the mm": there is none,
		 * copy_mm() sees to that. Nobody has to wait for the task, the
		 * pidfd tells. The rest is what every task of a cell gets.
		 */
		.flags		= CLONE_VM | CLONE_UNTRACED | CLONE_AUTOREAP |
				  CLONE_INTO_CGROUP | CLONE_NNP | CLONE_CLEAR_SIGHAND,
		.fn		= embryo_main,
		.fn_arg		= e,
		.name		= "embryo",
		.pid		= e->pid,
		.cell		= e->cell,
		.embryo		= e,
	};
	pid_t nr;
	int ret;

	/* Until embryo_fork_finish(). */
	ret = cell_fork_prepare(e->cell);
	if (ret)
		return ret;

	scoped_guard(mutex, &e->lock) {
		ret = e->started ? -EBUSY : e->exec ? 0 : -EINVAL;
		if (!ret)
			e->started = true;
	}
	if (ret) {
		cell_fork_finish(e->cell);
		return ret;
	}

	/* For the task. */
	refcount_inc(&e->ref);
	nr = kernel_clone(&args);
	if (nr < 0) {
		scoped_guard(mutex, &e->lock)
			embryo_drop_config(e);
		return nr;
	}

	/*
	 * Everything up to the point of no return of the exec is reported
	 * here. Past that it is a fatal signal, for the pidfd to tell.
	 */
	if (wait_for_completion_killable(&e->done))
		return -EINTR;
	return e->result;
}

/**
 * sys_pidfd_configure - say what the task of an empty pidfd is to be, and start it
 * @pidfd:  what pidfd_open() returned for PIDFD_EMPTY, and no other pidfd
 * @cmd:    one of enum pidfd_configure_cmd
 * @ukey:   the name of what is set, or NULL for PIDFD_CMD_START
 * @uvalue: a string for PIDFD_SET_STRING, @aux bytes for PIDFD_SET_BINARY
 * @aux:    a length for PIDFD_SET_BINARY, a file descriptor for PIDFD_SET_FD
 *
 * Shaped like fsconfig(). Data only goes in.
 *
 * PIDFD_CMD_START makes the task, applies everything in its context, has it exec
 * and waits for that. Whatever goes wrong is returned here, and the task, if it
 * got that far, is killed. It can be tried only once.
 *
 * Return: 0, -EPERM for any other pidfd, -EBUSY once it was started, -ESRCH if
 * the task or the cell was killed, -EOPNOTSUPP for an unknown @cmd, -EINVAL for
 * an unknown key or arguments that do not go with @cmd, or what went wrong.
 */
SYSCALL_DEFINE5(pidfd_configure, int, pidfd, unsigned int, cmd,
		const char __user *, ukey, const void __user *, uvalue, int, aux)
{
	char *key __free(kfree) = NULL;
	char *str __free(kfree) = NULL;
	struct embryo *e;
	int ret;

	switch (cmd) {
	case PIDFD_SET_STRING:
		if (!ukey || !uvalue || aux)
			return -EINVAL;
		break;
	case PIDFD_SET_BINARY:
		if (!ukey || !uvalue || aux <= 0)
			return -EINVAL;
		break;
	case PIDFD_SET_FD:
		if (!ukey || uvalue || aux < 0)
			return -EINVAL;
		break;
	case PIDFD_CMD_START:
		if (ukey || uvalue || aux)
			return -EINVAL;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (ukey) {
		key = strndup_user(ukey, EMBRYO_KEY_MAX);
		if (IS_ERR(key))
			return PTR_ERR(no_free_ptr(key));
	}
	if (cmd == PIDFD_SET_STRING) {
		str = strndup_user(uvalue, PATH_MAX);
		if (IS_ERR(str))
			return PTR_ERR(no_free_ptr(str));
	}

	CLASS(fd, f)(pidfd);
	if (fd_empty(f))
		return -EBADF;
	e = embryo_from_file(fd_file(f));
	if (IS_ERR(e))
		return PTR_ERR(e);

	if (cmd == PIDFD_CMD_START)
		return embryo_start(e);

	mutex_lock(&e->lock);
	ret = -EBUSY;
	if (e->started)
		goto out;

	switch (cmd) {
	case PIDFD_SET_STRING:
		ret = -EINVAL;
		if (strcmp(key, "exec"))
			break;
		kfree(e->exec);
		e->exec = no_free_ptr(str);
		ret = 0;
		break;
	case PIDFD_SET_BINARY:
		if (!strcmp(key, "argv"))
			ret = embryo_set_strings(&e->argv, uvalue, aux);
		else if (!strcmp(key, "envp"))
			ret = embryo_set_strings(&e->envp, uvalue, aux);
		else if (!strcmp(key, "cred"))
			ret = embryo_set_cred(e, uvalue, aux);
		else
			ret = -EINVAL;
		break;
	case PIDFD_SET_FD: {
		CLASS(fd, slot)(aux);

		ret = -EBADF;
		if (!fd_empty(slot))
			ret = embryo_set_fd(e, key, fd_file(slot));
		break;
	}
	}
out:
	mutex_unlock(&e->lock);
	return ret;
}
