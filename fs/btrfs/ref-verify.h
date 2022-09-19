/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014 Facebook.  All rights reserved.
 */

#ifndef BTRFS_REF_VERIFY_H
#define BTRFS_REF_VERIFY_H

#ifdef CONFIG_BTRFS_FS_REF_VERIFY
int btrfs_build_ref_tree(struct btrfs_fs_info *fs_info);
void btrfs_free_ref_cache(struct btrfs_fs_info *fs_info);
int btrfs_ref_tree_mod(struct btrfs_fs_info *fs_info,
		       struct btrfs_ref *generic_ref);
void btrfs_free_ref_tree_range(struct btrfs_fs_info *fs_info, u64 start,
			       u64 len);
#else
static inline int btrfs_build_ref_tree(struct btrfs_fs_info *fs_info)
{
	return 0;
}

static inline void btrfs_free_ref_cache(struct btrfs_fs_info *fs_info)
{
}

static inline int btrfs_ref_tree_mod(struct btrfs_fs_info *fs_info,
		       struct btrfs_ref *generic_ref)
{
	return 0;
}

static inline void btrfs_free_ref_tree_range(struct btrfs_fs_info *fs_info,
					     u64 start, u64 len)
{
}
#endif /* CONFIG_BTRFS_FS_REF_VERIFY */

#endif
