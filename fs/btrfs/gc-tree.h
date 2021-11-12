/* SPDX-License-Identifier: GPL-2.0 */

#ifndef BTRFS_GC_TREE_H
#define BTRFS_GC_TREE_H

struct btrfs_fs_info;
struct btrfs_inode;
struct btrfs_block_rsv;

void btrfs_queue_gc_work(struct btrfs_fs_info *fs_info);
int btrfs_add_inode_gc_item(struct btrfs_inode *inode,
			    struct btrfs_block_rsv *rsv);

#endif

