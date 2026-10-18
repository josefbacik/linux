.. SPDX-License-Identifier: GPL-2.0

=====
Cells
=====

A cell is a container as one kernel object.  A task is born in a cell and never
leaves it, and nothing can enter one.  A cell is built from the outside: the
builder fills named slots from file descriptors it holds, seals the cell, and
spawns tasks into it.  Holding the file descriptor of the cell, the *cellfd*, is
the authority to do all of that.

This document explains why cells exist, what they promise, how they are used and
what the first implementation does not do yet.  "Cell" is a working name.

.. contents:: :local:


Why
===

A container on Linux is not an object.  It is eight kinds of namespace, a cgroup,
a seccomp filter and a set of conventions that a runtime holds together.  A number
of problems follow from that, and they do not go away by fixing bugs one at a
time.

There is nothing to name.
  The kernel cannot say which container a task is in, cannot kill a container in
  one operation and cannot tell what a container has access to.

Membership is a property of a task at a moment.
  ``setns()`` and ``unshare()`` let a task change one namespace at a time.  A task
  that is half way between two sets of namespaces, holding file descriptors, a
  working directory or a memory map from one side and credentials from the other,
  has been the source of many bugs.

Setup runs on the inside.
  A runtime forks, and the child sheds, one call at a time, what it inherited and
  should not have.  What it forgets to shed leaks into the container.

Privilege hangs off ids.
  A user namespace gives its creator a full set of capabilities over everything
  the namespace owns, which puts a large amount of code that was written for root
  within reach of every user.  Who may do what to whom is decided by comparing
  uids, and whether two uids are the same depends on how several runtimes agreed
  to carve up ``/etc/subuid``.

Hiding is done by mounting over.
  What a container must not see is commonly covered by a mount.  ``MNT_LOCKED``
  exists to keep such mounts in place, and a way to remove one, or to copy the tree
  without it, reveals what it covered.

A cell turns this around.  There is one object with one lifetime.  What it holds
was put there explicitly, by somebody who held it.  What was not put there is not
there.


The model
=========

Invariants
----------

The implementation is meant to uphold the following.  A way to break one of them
from the inside of a cell, or as an unprivileged user outside, is a bug.

#. **A task never changes cell.**  There is no way to enter a cell and no way to
   leave one.  The namespaces of a cell belong to the cell and not to its tasks.
#. **A cell holds what it was given.**  Slots are filled from file descriptors the
   builder holds.  Filling a slot takes what using the object would take.
#. **Authority over a cell is the cellfd.**  No uid and no capability is compared
   when a cell is configured, spawned into or killed.  There is no cell without
   somebody who holds one: it dies with the last.
#. **Nothing is inherited that gives access to anything.**  A task that is spawned
   into a cell starts with no memory map and no open files.  What it can reach is
   what it was given.  `Spawning: embryo tasks`_ lists what it does inherit.
#. **After that nothing crosses.**  Once a task has started, no file descriptor and
   no identity crosses the boundary of its cell.  A cell that was given a network
   namespace to share is an exception, see `Not there yet`_.
#. **A cell starts nothing it was not allowed to.**  Making a cell and starting a
   task in one is a slot like any other, ``spawn``.  It cannot be filled yet, so what
   runs in a cell comes from a ``fork()`` and ``execve()`` of what was spawned into
   it, or from outside.
#. **A uid means nothing across cells.**  Not an equal one, and not 0.
#. **Files impart no privilege.**  Nothing a cell runs can gain privilege from a
   file, and nothing a cell writes can give privilege to anybody else.
#. **Nothing is hidden by a mount.**  Whatever is in the tree of a cell, the cell
   may see all of it, including what lies under every mount point.
#. **Ids are lent.**  The kernel chooses the kuids and kgids of a block, nobody else
   can hold one of them while the cell does, and nothing the cell made may still be
   owned by one when they are lent again.
#. **DEAD means gone.**  When a cell reports that it is dead, no task of it is left,
   not even one that is on its way out, and the cell has dropped every reference it
   held.  What that sets off, such as the release of mounts, of the network
   namespace and of the block of ids, completes on its own time.

Life of a cell
--------------

A cell only ever moves down this list.

=================  =============================================================
``CELL_BUILDING``  Slots may be filled.  Nothing runs.
``CELL_SEALED``    Immutable.  Nothing has been spawned yet.
``CELL_RUNNING``   Has, or had, its first task.
``CELL_DYING``     Was killed, or its first task has exited.
``CELL_DEAD``      Nothing is left.  The exit status can be read.
=================  =============================================================

The first task that is spawned is the init of the pid namespace of the cell.  When
it exits the kernel kills everything else in that namespace, as it does for any pid
namespace, and the cell dies.

A cell can be killed in every state.

**A cell lives for as long as somebody holds a cellfd on it, and no longer.**  When the
last one is closed, be it because whoever held it was killed, the cell is killed.  A
cellfd can be passed on, so a cell can be handed to a supervisor, but a cell that nobody
holds is a cell that nobody could kill, spawn into or wait for.

Slots
-----

============  =========================================  =======================
Slot          Filled with                                If it is left empty
============  =========================================  =======================
``ids``       a count: 1 or 65536                        1; refused for root
``root``      a mount namespace nobody has entered       the seal fails
``budget``    a cgroup v2 directory                      the seal fails
``net``       the string ``"new"``, or a network         a new, empty one
              namespace to share
``hostname``  a string                                   ``(none)``
``spawn``     nothing yet, the name is reserved          no task of the cell can
                                                         make a cell or start a
                                                         task in one
============  =========================================  =======================

The pid, ipc, uts and cgroup namespaces of a cell are always new.  The cgroup
namespace is rooted at the budget.  The time namespace is that of the builder.

The network namespace of one cell cannot be shared with another, in whatever state
either is.  The tasks of the cell that owns it have every capability over it.


Ids
===

Every consumer of a kuid in the kernel knows how to deal with a user namespace, so
a cell has one.  The kernel makes it together with the cell, and it differs from a
legacy user namespace in the ways that make a legacy one hard to reason about:

* Nobody can ``setns()`` into it.
* The uid that created it has no capability over it.
* Its map is set once, by the kernel, to ids the kernel chose.

All translation between the ids a cell sees and the ids on disk stays in the VFS,
in the idmapping of each mount of the tree.  See
Documentation/filesystems/idmappings.rst.

A cell comes in two shapes.

One id
  The cell runs on the uid and gid of whoever made it, under their own numbers, with
  the supplementary groups of its maker and without capabilities.  ``setgroups()`` is
  denied.  The groups are kept because a group can be there to deny something.  This
  shape is refused to root, since too much goes by the bare value of kuid 0, and to
  an id that lies in the window described below.

A block
  The cell sees uids and gids 0 to 65535.  They map to a block of 65536 kuids and
  kgids that the kernel allocates.  **The builder never names a kuid.**  It takes no
  privilege: a block that nobody holds gives access to nothing.  A user can hold
  ``user.max_cell_id_blocks`` of them.

The window
----------

Blocks come out of a window, the upper half of the id space less its last block:
2147483648 to 4294901759.

"Nobody else holds an id of this block" stands in for the privilege check that a
legacy user namespace needs before it may map a range.  So it is enforced rather
than assumed:

* A legacy user namespace cannot map into the window.
* **No create, chown or ACL stores an id of the window in a filesystem that the
  cell does not own.**  Creating a file and ``chown()`` fail with ``EOVERFLOW``,
  setting an ACL with ``EINVAL``.  Through a mount that is idmapped for the cell the
  id has become the on-disk id before the check is made, so that works.  The check
  goes by the value of the id and not by who is asking, because a stacking
  filesystem may create files with the credentials of whoever mounted it.
* A block lives as long as the user namespace object it was lent to, not as long as
  the cell.  Every credential, and every object that the namespace owns, pins the
  namespace.  That covers the inodes which the kernel makes on filesystems of its
  own and gives to the caller without asking: pipes, sockets, memfds, the slave of
  a pty.  Each lives no longer than a file that is open on it, and the file pins the
  credentials it was opened with.
* The idmapping of a mount holds a copy of the maps.  One that was made for a cell
  pins the user namespace as well, so a mount that is kept beyond the life of the
  cell keeps the block from being lent again.
* What the cell made below its budget is removed when the cell dies, and the budget
  returns to its owner.  If that fails the block is never lent again.
* Some tables are keyed by a bare kuid and pin nothing: ``struct user_struct`` and
  the quota records of keys.  A released block is quarantined until they hold
  nothing in its range, and a block is checked the same way before it is lent.

Blocks are handed out round robin, so that reuse comes as late as it can.  A block in
quarantine counts as used.  A leak therefore shows up as ``ENOSPC`` and never as one
tenant owning what another left behind.

.. warning::

   With ``CONFIG_CELLS`` enabled the host itself cannot ``chown()`` a file to an id
   of the window.  This is a change of behaviour for a system that uses such ids.
   Files that already belong to one, seen through a mount that is not idmapped,
   look as if they belonged to whichever cell is lent that block.

What the allocator does not cover is the ids on disk.  Through a mount that is
idmapped for it, a cell with a block always uses on-disk ids 0 to 65535, so two cells
that are given the same storage see each other's files.  That is sometimes intended,
as with shared images, and remains the responsibility of the builder.


The tree
========

The tree of a cell is built from scratch, one mount at a time, in a mount namespace
that nobody has entered: see ``fsmount(2)`` with ``FSMOUNT_NAMESPACE`` and
``open_tree(2)`` with ``OPEN_TREE_NAMESPACE``.  Sealing the cell makes that namespace
the cell's, or fails without having changed anything about it:

* No mount may be ``MNT_LOCKED``, since a locked mount hides what it covers.  The
  tree itself may be: it sits on the root of the namespace, which is empty, and the
  kernel locks it there for a builder that works in a user namespace of its own.
* Nobody is in the namespace, or on the way in.
* Every mount is made private.  Nothing propagates into a cell.
* In a cell with a block of ids, a writable mount of a filesystem that can be
  idmapped must be idmapped for the cell, or belong to a superblock the cell owns.
  This is only the early and readable form of the ``EOVERFLOW`` above.

To idmap a mount for a cell, pass the cellfd in ``mount_attr.userns_fd``.  On-disk
ids 0 to 65535 then belong to the ids of the cell, or the one id to itself.

A seal that fails leaves the cell ``CELL_BUILDING``.  What it had filled in for slots
that were left empty by then stays filled in.

The mount namespace stays owned by the user namespace of the builder.  That is what
keeps a task of the cell from mounting anything.


Spawning: embryo tasks
======================

``clone3()`` with ``CLONE_EMBRYO`` returns a pidfd on a task that exists but has
never run an instruction of user code, and never runs any of its creator's.  The
creator sets it up with ``task_configure()`` and starts it, at which point it execs.
The creator does not fork.  This is ``fsopen()`` for tasks.

An embryo has

* no memory map, from the start,
* an empty file table,
* the root of the tree of the cell as its root and working directory,
* the credentials of the root of the cell, or of its one id,
* default signal dispositions, nothing blocked and nothing pending,
* its own session and no controlling terminal,
* ``no_new_privs``,
* none of its creator's registers.

It still inherits attributes of its creator, as any new task does.  Among them are
resource limits, nice value, scheduling policy and affinity, the core scheduling
cookie, ``oom_score_adj``, I/O priority, memory policy, timer slack, the speculation
controls of ``prctl(2)``, perf events that are marked for inheritance, membership in
cgroup v1 hierarchies, the audit ids, **seccomp filters and LSM state**.  The list is
not complete.  The last two are deliberate: what a confined task spawns is confined as
it is itself.

For LSMs that covers the start as well.  The hooks for receiving a file, for changing
ids and for every step of an exec are called in the context of the embryo, with the
state it inherited.

.. warning::

   For seccomp it does not.  The filters apply to every system call the new program
   makes.  They are **not** consulted for what ``TASK_CMD_START`` does on the way
   there, since the new session, the files, the credentials and the exec are not
   system calls of the embryo.  A filter that denies ``execve()`` and ``execveat()``
   to keep a task from running another program does not keep it from starting one in
   a cell.  Such a filter has to deny ``task_configure()`` too, without which an embryo
   never runs, as it once had to learn about ``execveat()``.

   This is about a task of the host.  A task of a cell cannot start an embryo at all,
   see the ``spawn`` slot.  Evaluating the filters at the start may be added later.

The listener of a filter with ``SECCOMP_RET_USER_NOTIF`` stays behind, outside of the
cell.  It goes on answering for the system calls of what was spawned.  It cannot put a
file into it: ``SECCOMP_IOCTL_NOTIF_ADDFD`` fails with ``EPERM`` across cells.

Only the file that ``clone3()`` returned can configure an embryo.  Another pidfd on
the same task cannot.  An embryo whose file is closed before it was started is
killed.  Nobody can ptrace an embryo, or read the files in its ``/proc`` directory
that are gated by ptrace access.

===================  ==================  ========================================
Command              Key                 Value
===================  ==================  ========================================
``TASK_SET_STRING``  ``exec``            the path to execute, in the cell's tree
``TASK_SET_BINARY``  ``argv``, ``envp``  NUL terminated strings, back to back
``TASK_SET_BINARY``  ``cred``            ``struct task_cred``, in the cell's ids
``TASK_SET_FD``      a decimal number    the file to have at that number
``TASK_CMD_START``   none                apply everything and exec
===================  ==================  ========================================

The file table of the new task is exactly what was put there.  io_uring files,
cellfds, namespace files and the pidfd of an embryo are refused.

Whatever goes wrong is returned by ``TASK_CMD_START``, and the embryo is killed, which
is what the pidfd reports.  If it was to be the first task of the cell, the cell dies
with it.

The pid namespace of the spawner must be an ancestor of that of the cell.  For now
``CLONE_EMBRYO`` and ``CLONE_INTO_CELL`` need each other, ``CLONE_PIDFD`` and
``CLONE_AUTOREAP``.


The boundary
============

Namespaces
----------

For a task of a cell ``setns()``, ``unshare()`` and ``clone()`` with any
``CLONE_NEW*`` flag fail with ``EPERM``, as do ``OPEN_TREE_NAMESPACE`` and
``FSMOUNT_NAMESPACE``.

From the outside ``setns()`` into a namespace of a cell fails with ``EPERM``.  The one
exception is the network namespace of a cell that is still being built, which is how
the tools that configure networks work today.  Whoever is in there when the cell is
sealed stays there, so it is for the builder to see that nobody is.  The pid namespace
is no exception: whoever got in there could become the init of the cell with the
credentials of the host.

Tasks
-----

A one-id cell runs on the kuid of its maker, and the pids of a cell are visible from
above.  So wherever one task acts on another and an equal uid is enough, the same
cell is required as well: signals, ptrace, scheduling attributes, priorities, I/O
priorities, resource limits, ``SIGIO``, moving a task between cgroup v1 or resctrl
groups, and ``KEYCTL_SESSION_TO_PARENT``.

There used to be a copy of such a check wherever one was needed, and a copy that is
overlooked is a way out of a cell.  They have been gathered in one place, see
"Comparing the Ids of Two Tasks" in Documentation/security/credentials.rst, and the
rule about cells is applied there, once, ahead of every one of them.  That includes
the two that let euid 0 act on anybody: root on the host can neither have ``SIGIO``
sent to a task of a cell nor move one between cgroup v1 or resctrl groups.  This is a
hard boundary.  A cell that is not as it should be is killed and built again.

The owner and group permissions of a key likewise only count within the cell the key
was made in.

``PTRACE_TRACEME`` fails across cells.  The parent of a task that was spawned into a
cell is the spawner, outside.

The capability branch of each of these checks is unchanged for now.  See
`Not there yet`_.

Files
-----

A file can hand a process privilege at exec, by its set-id bits or by its file
capabilities.  In a cell both are impossible.

*Running.*  Every task of a cell has ``no_new_privs``, which cannot be unset and is
inherited.

*Writing.*  The ids of a cell commonly map to on-disk ids from 0 up, because that is
how images are stored.  A set-uid bit that the root of a cell sets would make a
set-uid root file for whoever else looks at that filesystem.  So:

* No task of a cell ever has ``CAP_SETFCAP``, not even in its bounding set, so it
  cannot write a file capability.
* ``S_ISUID``, and ``S_ISGID`` on anything but a directory, are silently dropped from
  the mode of what a task of a cell creates and from the mode it sets.  They are
  dropped and not refused so that unpacking an archive keeps working.
* The set-id bits and file capabilities of an existing file are dropped as soon as a
  task of a cell opens it for writing, or is given it open for writing.  A
  ``write()`` drops them, a store through a shared mapping does not.

``sudo``, ``su`` run by anybody but root, ``pkexec``, and tools that rely on a set-gid
bit or a file capability do not work in a cell.  A daemon that starts as root and
drops privileges with ``setuid()`` works as ever.

Unix sockets
------------

A unix socket can span two cells, because both can see the tree it is bound in or
because one end was given to a new task.  **Between cells it carries bytes and nothing
else.**

* Ancillary data is delivered only within a cell.  Every message records the cell it
  was sent from, and whoever receives it gets the files, the credentials, the pidfd
  and the security label only if that is its own cell.  This covers a file that was
  queued on a socket before the socket was given away.
* Sending control data to a socket that another cell holds fails with ``EPERM``, where
  that can be known at the time.
* ``SO_PEERCRED``, ``SO_PEERGROUPS``, ``SO_PEERPIDFD`` and ``SO_PEERSEC`` fail with
  ``ENODATA`` if the peer is in another cell.  They fail rather than report the
  overflow ids: 65534 is a uid like any other inside a cell, and a server that lets
  in whoever has its own uid may well be running as it.

Peer credentials are not a way to authorise anything between cells.  Protocols that
pass file descriptors to a service in another cell do not work.

The budget
----------

The budget of a cell bounds what the cell can use and is how the kernel finds every
task in it.  It belongs to one cell: when the slot is filled the cgroup must be empty,
have no children, and neither be nor lie within the budget of another cell.  Whoever
fills the slot needs everything that moving a task of its own there would take, and
must own the directory.

A task of a cell stays within the budget, whoever asks.  Nothing but a spawn gets a
task into one, kernel threads included.

On a cgroup v1 hierarchy a task of a cell is where its spawner was, and no request
moves it.  The kernel itself may: out of a cpuset that lost its last cpu, to the
nearest ancestor that has one.

Sealing hands the directory, ``cgroup.procs``, ``cgroup.threads`` and
``cgroup.subtree_control`` to the root of the cell.  The limits stay with whoever is
above.


The system calls
================

They are split by what they do, as the mount API is, so that "may look but not touch"
is a system call number: ``cell_info()`` changes nothing.

.. code-block:: c

   int cell_create(int parent, unsigned int flags);
   int cell_configure(int cfd, unsigned int cmd, const char *key,
                      const void *value, int aux);
   int cell_info(int cfd, struct cell_info *info, size_t size,
                 unsigned int flags);
   int cell_open(int cfd, unsigned int what, const char *key, const void *arg,
                 unsigned int flags);
   int task_configure(int pidfd, unsigned int cmd, const char *key,
                      const void *value, int aux);

``cell_create()``
  makes a new, empty cell and returns a cellfd, which is always close-on-exec.
  ``parent`` is ``CELL_SELF``.  It takes no privilege, but it makes a user namespace,
  and what applies to those applies here: ``user.max_user_namespaces``, the LSM hook,
  and no chrooted caller.

``cell_configure()``
  changes a cell.  It is shaped like ``fsconfig(2)`` and data only goes in.

``cell_info()``
  reads from a cell.  The struct can grow: the caller says in ``mask`` what it wants,
  the kernel says there what it filled in, and in ``supported_mask`` what it knows of.
  With ``CELL_SELF`` for a cellfd it tells a task the id of its own cell.

``cell_open()``
  gets another file descriptor from a cell.  For now that is an nsfs file descriptor
  on the network (``"net"``) or pid (``"pids"``) namespace of a cell that is being
  built.  The namespace is made if the cell does not have it yet, which fills the
  slot.

``task_configure()``
  sets up and starts an embryo.

A cellfd polls readable once the cell is dead, and ``read(2)`` then returns the wait
status of its first task as an ``int``, any number of times.  A cellfd can be passed on
but cannot be opened again through ``/proc/<pid>/fd``.

Every cell has a 64 bit id that is never reused.  It is the inode number of the
cellfd.

Example
-------

Error handling is left out.

.. code-block:: c

   unsigned int ids = 65536;
   int cfd, tree, pidns, fs, proc, ns, pidfd, status;

   cfd = cell_create(CELL_SELF, 0);
   cell_configure(cfd, CELL_SET_BINARY, "ids", &ids, sizeof(ids));

   /* The tree, from scratch.  The image becomes "/", for this cell. */
   struct mount_attr attr = {
           .attr_set  = MOUNT_ATTR_IDMAP,
           .userns_fd = cfd,
   };
   tree = open_tree_attr(AT_FDCWD, "/images/web", OPEN_TREE_CLONE,
                         &attr, sizeof(attr));

   /* A procfs for the pid namespace of the cell. */
   pidns = cell_open(cfd, CELL_OPEN_SLOT, "pids", NULL, 0);
   fs = fsopen("proc", 0);
   fsconfig(fs, FSCONFIG_SET_FD, "pidns", NULL, pidns);
   fsconfig(fs, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
   proc = fsmount(fs, 0, 0);
   move_mount(proc, "", tree, "proc", MOVE_MOUNT_F_EMPTY_PATH);

   ns = open_tree(tree, "", AT_EMPTY_PATH | AT_RECURSIVE | OPEN_TREE_NAMESPACE);

   cell_configure(cfd, CELL_SET_FD, "root", NULL, ns);
   cell_configure(cfd, CELL_SET_FD, "budget", NULL, cgroup_dirfd);
   cell_configure(cfd, CELL_SET_STRING, "hostname", "web-1", 0);
   cell_configure(cfd, CELL_CMD_SEAL, NULL, NULL, 0);

   struct clone_args ca = {
           .flags = CLONE_PIDFD | CLONE_EMBRYO | CLONE_INTO_CELL | CLONE_AUTOREAP,
           .pidfd = (uintptr_t)&pidfd,
           .cell  = cfd,
   };
   clone3(&ca, sizeof(ca));        /* the caller does not fork */

   task_configure(pidfd, TASK_SET_STRING, "exec", "/usr/sbin/nginx", 0);
   task_configure(pidfd, TASK_SET_BINARY, "argv", "nginx\0-g\0daemon off;", 21);
   task_configure(pidfd, TASK_SET_FD, "1", NULL, log_fd);
   task_configure(pidfd, TASK_SET_FD, "2", NULL, log_fd);
   task_configure(pidfd, TASK_CMD_START, NULL, NULL, 0);

   read(cfd, &status, sizeof(status));     /* until the cell is dead */


Not there yet
=============

The first implementation is deliberately small.  It exists so that there is code to
argue about.

What a builder can still get wrong
----------------------------------

These are mistakes of a privileged builder, of the kind a container runtime can make
today.  None of them can be reached from the inside.

* There are no per-cell instances of procfs, sysfs, devtmpfs and cgroupfs.  The
  builder assembles those with what exists today, and can mount a procfs that shows
  the whole host.  The direction is for each of the four to take the cell as a mount
  parameter, show only what the cell holds, and be refused to a task of any other
  cell.
* There is no table of devices a cell may use.  The builder can put any device node
  into the tree.  Devices that create devices, such as ``loop-control``, must not be
  given to a cell.
* The list of files for a new task is only lightly filtered.  The builder can pass a
  plain directory of the host.
* A cellfd that sits in a message on a unix socket counts as held.  A builder that
  queues the cellfd of a cell on a socket, gives the other end to a task of that cell
  and closes the rest is left with a cell that nobody can reach.  It is killed when
  the message is read, since the file does not cross, or when the socket goes.

What does not work yet
----------------------

* **Spawning from the outside fails with** ``EBUSY`` **once the cell has enabled
  controllers on its budget**, by the rule that a cgroup with controllers enabled for
  its children has no tasks of its own.  An init that manages cgroups does that right
  away.  It needs a leaf below the budget for spawns to land in.
* **A cell with a block of ids cannot create a cgroup.**  The superblock of cgroupfs
  belongs to the host, so the ids of the cell cannot be stored there.  It needs
  cgroupfs to be idmappable.
* The cgroup v2 freezer does not report a budget as frozen while an embryo in it has
  not been started.
* ``RLIMIT_NPROC`` is not applied to the uid that is set with ``cred``.
* The seccomp filters of an embryo are not consulted for its exec, see
  `Spawning: embryo tasks`_.
* There are no rights on a cellfd.  Every cellfd can do everything.
* Cells do not nest, since the ``spawn`` slot cannot be filled, and a task of a cell
  cannot create any kind of namespace, so
  software that sandboxes itself with namespaces does not work in a cell.
* A cell cannot outlive its last cellfd, and there is no way to find one again by its
  id.  What is to run for long needs somebody who holds on to it for as long.
* Only x86 and the architectures that use the generic system call table are wired up.
* There are no LSM hooks for the new operations, other than those that come with the
  user namespace, the exec and the files.
* **A network namespace that is shared with a cell carries identities.**  Only unix
  sockets know about cells.  ``SCM_CREDENTIALS`` on a netlink socket says who sent a
  message, and ``NETLINK_USERSOCK`` lets any two tasks of a network namespace talk.

What is still decided the old way
---------------------------------

* **A capability in an ancestor user namespace still applies to what a cell owns.**
  Root on the host can signal and ptrace the tasks of a cell by pid and configure its
  network namespace.  Only the branch of each check that goes by a uid has been
  closed.
* Files in ``/proc/<pid>`` that are protected by nothing but their owner, such as
  ``oom_score_adj``, still go by the bare uid.
* A one-id cell shares the ``struct user_struct`` and the key quota of its maker.
* Nothing keeps root on the host from calling ``setresuid()`` with an id of a block
  that has been lent, or from mounting a filesystem with such an id for an option.
