// SPDX-License-Identifier: GPL-2.0

#include "ctree.h"
#include "gc-tree.h"
#include "btrfs_inode.h"
#include "disk-io.h"
#include "transaction.h"
#include "inode-item.h"

struct gc_work {
	struct btrfs_work work;
	struct btrfs_root *root;
};

static struct btrfs_root *inode_gc_root(struct btrfs_inode *inode)
{
	struct btrfs_fs_info *fs_info = inode->root->fs_info;
	struct btrfs_key key = {
		.objectid = BTRFS_GC_TREE_OBJECTID,
		.type = BTRFS_ROOT_ITEM_KEY,
		.offset = btrfs_ino(inode) % fs_info->nr_global_roots,
	};

	return btrfs_global_root(fs_info, &key);
}

static int add_gc_item(struct btrfs_root *root, struct btrfs_key *key,
		       struct btrfs_block_rsv *rsv)
{
	struct btrfs_path *path;
	struct btrfs_trans_handle *trans;
	int ret = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	trans = btrfs_gc_rsv_refill_and_join(root, rsv);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto out;
	}

	trans->block_rsv = rsv;
	ret = btrfs_insert_empty_item(trans, root, path, key, 0);
	trans->block_rsv = &root->fs_info->trans_block_rsv;
	btrfs_end_transaction(trans);
out:
	btrfs_free_path(path);
	return ret;
}

static void delete_gc_item(struct btrfs_root *root, struct btrfs_path *path,
			   struct btrfs_block_rsv *rsv, struct btrfs_key *key)
{
	struct btrfs_trans_handle *trans;
	int ret;

	trans = btrfs_gc_rsv_refill_and_join(root, rsv);
	if (IS_ERR(trans))
		return;

	ret = btrfs_search_slot(trans, root, key, path, -1, 1);
	if (ret > 0)
		ret = -ENOENT;
	if (ret < 0)
		return;
	btrfs_del_item(trans, root, path);
	btrfs_release_path(path);
	btrfs_end_transaction(trans);
}

static int gc_inode(struct btrfs_fs_info *fs_info, struct btrfs_block_rsv *rsv,
		    struct btrfs_key *key)
{
	struct btrfs_root *root = btrfs_get_fs_root(fs_info, key->objectid, true);
	struct btrfs_trans_handle *trans;
	int ret = 0;

	if (IS_ERR(root)) {
		ret = PTR_ERR(root);

		/* We are deleting this subvolume, just delete the GC item for it. */
		if (ret == -ENOENT)
			return 0;

		btrfs_err(fs_info, "failed to look up root during gc %llu: %d",
			  key->objectid, ret);
		return ret;
	}

	do {
		struct btrfs_truncate_control control = {
			.ino = key->offset,
			.new_size = 0,
			.min_type = 0,
		};

		trans = btrfs_gc_rsv_refill_and_join(root, rsv);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			break;
		}

		trans->block_rsv = rsv;

		ret = btrfs_truncate_inode_items(trans, root, &control);

		trans->block_rsv = &fs_info->trans_block_rsv;
		btrfs_end_transaction(trans);
		btrfs_btree_balance_dirty(fs_info);
	} while (ret == -ENOSPC || ret == -EAGAIN);

	btrfs_put_root(root);
	return ret;
}

static void gc_work_fn(struct btrfs_work *work)
{
	struct gc_work *gc_work = container_of(work, struct gc_work, work);
	struct btrfs_root *root = gc_work->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_path *path;
	struct btrfs_block_rsv *rsv;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		goto out;

	rsv = btrfs_alloc_block_rsv(fs_info, BTRFS_BLOCK_RSV_TEMP);
	if (!rsv)
		goto out_path;
	rsv->size = btrfs_calc_metadata_size(fs_info, 1);
	rsv->failfast = 1;

	while (btrfs_fs_closing(fs_info) &&
	       !btrfs_first_item(root, path)) {
		struct btrfs_key key;

		btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
		btrfs_release_path(path);

		switch (key.type) {
		case BTRFS_GC_INODE_ITEM_KEY:
			ret = gc_inode(root->fs_info, rsv, &key);
			break;
		default:
			ASSERT(0);
			ret = -EINVAL;
			break;
		}

		if (!ret)
			delete_gc_item(root, path, rsv, &key);
	}
	btrfs_free_block_rsv(fs_info, rsv);
out_path:
	btrfs_free_path(path);
out:
	clear_bit(BTRFS_ROOT_GC_RUNNING, &root->state);
	kfree(gc_work);
}

/**
 * btrfs_queue_gc_work - queue work for non-empty GC roots.
 * @fs_info: The fs_info for the file system.
 *
 * This walks through all of the garbage collection roots and schedules the
 * work structs to chew through their work.
 */
void btrfs_queue_gc_work(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root;
	struct gc_work *gc_work;
	struct btrfs_key key = {
		.objectid = BTRFS_GC_TREE_OBJECTID,
		.type = BTRFS_ROOT_ITEM_KEY,
	};
	int nr_global_roots = fs_info->nr_global_roots;
	int i;

	if (!btrfs_fs_incompat(fs_info, EXTENT_TREE_V2))
		return;

	if (btrfs_fs_closing(fs_info))
		return;

	for (i = 0; i < nr_global_roots; i++) {
		key.offset = i;
		root = btrfs_global_root(fs_info, &key);
		if (test_and_set_bit(BTRFS_ROOT_GC_RUNNING, &root->state))
			continue;
		gc_work = kmalloc(sizeof(struct gc_work), GFP_KERNEL);
		if (!gc_work) {
			clear_bit(BTRFS_ROOT_GC_RUNNING, &root->state);
			continue;
		}
		gc_work->root = root;
		btrfs_init_work(&gc_work->work, gc_work_fn, NULL, NULL);
		btrfs_queue_work(fs_info->gc_workers, &gc_work->work);
	}
}

/**
 * btrfs_add_inode_gc_item - add a gc item for an inode that needs to be removed.
 * @inode: The inode that needs to have a gc item added.
 * @rsv: The block rsv to use for the reservation.
 *
 * This adds the gc item for the given inode.  This must be called during evict
 * to make sure nobody else is going to access this inode.
 */
int btrfs_add_inode_gc_item(struct btrfs_inode *inode,
			    struct btrfs_block_rsv *rsv)
{
	struct btrfs_key key = {
		.objectid = inode->root->root_key.objectid,
		.type = BTRFS_GC_INODE_ITEM_KEY,
		.offset = btrfs_ino(inode),
	};

	return add_gc_item(inode_gc_root(inode), &key, rsv);
}
