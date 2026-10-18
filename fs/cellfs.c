// SPDX-License-Identifier: GPL-2.0-only
/*
 * cellfs: the pseudo filesystem a cellfd lives on.
 *
 * Modelled on pidfs. One inode per cell, numbered by the cell's id, which is
 * never reused. The inode holds a reference on the cell.
 */
#include <linux/cell.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>

#include "internal.h"

static struct vfsmount *cellfs_mnt __ro_after_init;

static void cellfs_evict_inode(struct inode *inode)
{
	struct cell *cell = inode->i_private;

	clear_inode(inode);
	cell_put(cell);
}

static const struct super_operations cellfs_sops = {
	.drop_inode	= inode_just_drop,
	.evict_inode	= cellfs_evict_inode,
	.statfs		= simple_statfs,
};

static char *cellfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(buffer, buflen, "cell:[%llu]",
			     d_inode(dentry)->i_ino);
}

static const struct dentry_operations cellfs_dentry_operations = {
	.d_dname	= cellfs_dname,
	.d_prune	= stashed_dentry_prune,
};

static int cellfs_setattr(const struct mnt_idmap *idmap, struct dentry *dentry,
			  struct iattr *attr)
{
	return -EOPNOTSUPP;
}

static const struct inode_operations cellfs_inode_operations = {
	.setattr	= cellfs_setattr,
};

static int cellfs_init_inode(struct inode *inode, void *data)
{
	struct cell *cell = data;

	inode->i_private = data;
	inode->i_flags |= S_PRIVATE | S_ANON_INODE;
	inode->i_mode |= 0700;
	inode->i_op = &cellfs_inode_operations;
	inode->i_fop = &cell_file_operations;
	inode->i_ino = cell_id(cell);
	return 0;
}

static void cellfs_put_data(void *data)
{
	cell_put(data);
}

static const struct stashed_operations cellfs_stashed_ops = {
	.init_inode	= cellfs_init_inode,
	.put_data	= cellfs_put_data,
};

static int cellfs_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx;

	ctx = init_pseudo(fc, CELL_FS_MAGIC);
	if (!ctx)
		return -ENOMEM;

	ctx->s_d_flags |= DCACHE_DONTCACHE;
	ctx->ops = &cellfs_sops;
	ctx->dops = &cellfs_dentry_operations;
	fc->s_fs_info = (void *)&cellfs_stashed_ops;
	return 0;
}

static struct file_system_type cellfs_type = {
	.name			= "cellfs",
	.init_fs_context	= cellfs_init_fs_context,
	.kill_sb		= kill_anon_super,
};

/**
 * cell_from_file - the cell a file is a handle on
 * @file: any file
 *
 * Return: the cell, or NULL if @file is no cellfd. No reference is taken: @file
 * pins the inode, which holds one.
 */
struct cell *cell_from_file(const struct file *file)
{
	if (file->f_op != &cell_file_operations)
		return NULL;
	return file_inode(file)->i_private;
}

/**
 * cellfs_alloc_file - make a new handle on a cell
 * @cell: the cell. The caller keeps its own reference
 *
 * This is the only way to a handle. A cellfd cannot be opened again through
 * /proc/<pid>/fd.
 *
 * Return: a file open for reading and writing, or an ERR_PTR().
 */
struct file *cellfs_alloc_file(struct cell *cell)
{
	struct path path __free(path_put) = {};
	int ret;

	ret = path_from_stashed(cell_stashed(cell), cellfs_mnt, cell_get(cell),
				&path);
	if (ret < 0)
		return ERR_PTR(ret);

	return dentry_open(&path, O_RDWR, current_cred());
}

static int __init cellfs_init(void)
{
	cellfs_mnt = kern_mount(&cellfs_type);
	if (IS_ERR(cellfs_mnt))
		panic("Failed to mount cellfs pseudo filesystem");
	return 0;
}
fs_initcall(cellfs_init);
