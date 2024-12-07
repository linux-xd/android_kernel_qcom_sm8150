// SPDX-License-Identifier: GPL-2.0

#include "fuse_i.h"

#include <linux/file.h>
#include <linux/fuse.h>
#include <linux/idr.h>

ssize_t fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	const struct cred *old_cred;
	struct fuse_file *ff = file->private_data;
	struct file *passthrough_filp = ff->passthrough.filp;

	if (!passthrough_filp->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	vma->vm_file = get_file(passthrough_filp);

	old_cred = override_creds(ff->passthrough.cred);
	ret = call_mmap(vma->vm_file, vma);
	revert_creds(old_cred);

	if (ret)
		fput(passthrough_filp);
	else
		fput(file);

	fuse_file_accessed(file, passthrough_filp);

	return ret;
}

int fuse_passthrough_open(struct fuse_dev *fud, u32 lower_fd)
{
	int res;
	struct file *passthrough_filp;
	struct fuse_conn *fc = fud->fc;
	struct inode *passthrough_inode;
	struct super_block *passthrough_sb;
	struct fuse_passthrough *passthrough;

	if (!fc->passthrough)
		return -EPERM;

	passthrough_filp = fget(lower_fd);
	if (!passthrough_filp) {
		pr_err("FUSE: invalid file descriptor for passthrough.\n");
		return -EBADF;
	}

	if (!passthrough_filp->f_op->read_iter ||
	    !passthrough_filp->f_op->write_iter) {
		pr_err("FUSE: passthrough file misses file operations.\n");
		res = -EBADF;
		goto err_free_file;
	}

	passthrough_inode = file_inode(passthrough_filp);
	passthrough_sb = passthrough_inode->i_sb;
	if (passthrough_sb->s_stack_depth >= FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("FUSE: fs stacking depth exceeded for passthrough\n");
		res = -EINVAL;
		goto err_free_file;
	}

	passthrough = kmalloc(sizeof(struct fuse_passthrough), GFP_KERNEL);
	if (!passthrough) {
		res = -ENOMEM;
		goto err_free_file;
	}

	passthrough->filp = passthrough_filp;
	passthrough->cred = prepare_creds();

	idr_preload(GFP_KERNEL);
	spin_lock(&fc->passthrough_req_lock);
	res = idr_alloc(&fc->passthrough_req, passthrough, 1, 0, GFP_ATOMIC);
	spin_unlock(&fc->passthrough_req_lock);
	idr_preload_end();

	if (res > 0)
		return res;

	fuse_passthrough_release(passthrough);
	kfree(passthrough);

err_free_file:
	fput(passthrough_filp);

	return res;
}

int fuse_passthrough_setup(struct fuse_conn *fc, struct fuse_file *ff,
			   struct fuse_open_out *openarg)
{
	struct fuse_passthrough *passthrough;
	int passthrough_fh = openarg->passthrough_fh;

	if (!fc->passthrough)
		return -EPERM;

	/* Default case, passthrough is not requested */
	if (passthrough_fh <= 0)
		return -EINVAL;

	spin_lock(&fc->passthrough_req_lock);
	passthrough = idr_remove(&fc->passthrough_req, passthrough_fh);
	spin_unlock(&fc->passthrough_req_lock);

	if (!passthrough)
		return -EINVAL;

	ff->passthrough = *passthrough;
	kfree(passthrough);

	return 0;
}

void fuse_passthrough_release(struct fuse_passthrough *passthrough)
{
	if (passthrough->filp) {
		fput(passthrough->filp);
		passthrough->filp = NULL;
	}
	if (passthrough->cred) {
		put_cred(passthrough->cred);
		passthrough->cred = NULL;
	}
}
