// This file is provided under a dual BSD/GPLv2 license.  When using or
// redistributing this file, you may do so under either license.
//
// GPL LICENSE SUMMARY
//
// Copyright(c) 2016-2018 Intel Corporation.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of version 2 of the GNU General Public License as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// Contact Information:
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
// Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
//
// BSD LICENSE
//
// Copyright(c) 2016-2018 Intel Corporation.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//   * Neither the name of Intel Corporation nor the names of its
//     contributors may be used to endorse or promote products derived
//     from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <asm/sgx_le.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/mutex.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0))
	#include <linux/sched/signal.h>
#else
	#include <linux/signal.h>
#endif
#include <linux/shmem_fs.h>
#include <linux/wait.h>
#include "sgx.h"

struct sgx_le_ctx {
	struct pid *tgid;
	char *argv[2];
	struct crypto_shash *tfm;
	struct mutex hash_lock;
	struct mutex launch_lock;
	struct rw_semaphore users;
	wait_queue_head_t wq;
	bool kernel_read;
	bool user_read;
	struct file *pipe;
	struct sgx_launch_request req;
};

struct sgx_le_ctx sgx_le_ctx;

static ssize_t sgx_le_ctx_fops_read(struct file *filp, char __user *buf,
				    size_t count, loff_t *off)
{
	struct sgx_le_ctx *ctx = filp->private_data;
	int ret;

	if (count != sizeof(ctx->req)) {
		pr_crit("%s: invalid count %lu\n", __func__, count);
		return -EIO;
	}

	ret = wait_event_interruptible(ctx->wq, ctx->user_read);
	if (ret)
		return -EINTR;

	ret = copy_to_user(buf, &ctx->req, count);
	ctx->user_read = false;

	return ret ? ret : count;
}

static ssize_t sgx_le_ctx_fops_write(struct file *filp, const char __user *buf,
				     size_t count, loff_t *off)
{
	struct sgx_le_ctx *ctx = filp->private_data;
	int ret;

	if (count != sizeof(ctx->req.output)) {
		pr_crit("%s: invalid count %lu\n", __func__, count);
		return -EIO;
	}

	ret = copy_from_user(&ctx->req.output, buf, count);
	if (!ret)
		ctx->kernel_read = true;
	wake_up_interruptible(&ctx->wq);

	return ret ? ret : count;
}

static const struct file_operations sgx_le_ctx_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.read = sgx_le_ctx_fops_read,
	.write = sgx_le_ctx_fops_write,
};

static int sgx_le_task_init(struct subprocess_info *subinfo, struct cred *new)
{
	struct sgx_le_ctx *ctx = (struct sgx_le_ctx *)subinfo->data;
	struct file *tmp_filp;
	unsigned long len;
	loff_t pos = 0;
	int ret;

	len = (unsigned long)&sgx_le_proxy_end - (unsigned long)&sgx_le_proxy;

	tmp_filp = shmem_file_setup("[sgx_le_proxy]", len, 0);
	if (IS_ERR(tmp_filp)) {
		ret = PTR_ERR(tmp_filp);
		return ret;
	}
	fd_install(SGX_LE_EXE_FD, tmp_filp);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
	ret = kernel_write(tmp_filp, &sgx_le_proxy, len, &pos);
#else
	ret = kernel_write(tmp_filp, sgx_le_proxy, len, pos);
#endif
	if (ret != len && ret >= 0)
		return -ENOMEM;
	if (ret < 0)
		return ret;

	tmp_filp = anon_inode_getfile("[/dev/sgx]", &sgx_fops, NULL, O_RDWR);
	if (IS_ERR(tmp_filp))
		return PTR_ERR(tmp_filp);
	fd_install(SGX_LE_DEV_FD, tmp_filp);

	tmp_filp = anon_inode_getfile("[sgx_le]", &sgx_le_ctx_fops, ctx,
				      O_RDWR);
	if (IS_ERR(tmp_filp))
		return PTR_ERR(tmp_filp);
	fd_install(SGX_LE_PIPE_FD, tmp_filp);

	ctx->tgid = get_pid(task_tgid(current));
	ctx->pipe = tmp_filp;

	return 0;
}

static void __sgx_le_stop(struct sgx_le_ctx *ctx)
{
	if (ctx->tgid) {
		fput(ctx->pipe);
		kill_pid(ctx->tgid, SIGKILL, 1);
		put_pid(ctx->tgid);
		ctx->tgid = NULL;
	}
}

void sgx_le_stop(struct sgx_le_ctx *ctx, bool update_users)
{
	if (update_users) {
		up_read(&ctx->users);
		if (!down_write_trylock(&ctx->users))
			return;
	}

	mutex_lock(&ctx->launch_lock);
	__sgx_le_stop(ctx);
	mutex_unlock(&ctx->launch_lock);

	if (update_users)
		up_write(&ctx->users);
}

static int __sgx_le_start(struct sgx_le_ctx *ctx)
{
	struct subprocess_info *subinfo;
	int ret;

	if (ctx->tgid)
		return 0;

	ctx->argv[0] = SGX_LE_EXE_PATH;
	ctx->argv[1] = NULL;

	subinfo = call_usermodehelper_setup(ctx->argv[0], ctx->argv,
					    NULL, GFP_KERNEL, sgx_le_task_init,
					    NULL, &sgx_le_ctx);
	if (!subinfo)
		return -ENOMEM;

	ret = call_usermodehelper_exec(subinfo, UMH_WAIT_EXEC);
	if (ret) {
		__sgx_le_stop(ctx);
		return ret;
	}

	return 0;
}

int sgx_le_start(struct sgx_le_ctx *ctx)
{
	int ret;

	down_read(&ctx->users);

	mutex_lock(&ctx->launch_lock);
	ret = __sgx_le_start(ctx);
	mutex_unlock(&ctx->launch_lock);

	if (ret)
		up_read(&ctx->users);

	return ret;
}

int sgx_le_init(struct sgx_le_ctx *ctx)
{
	struct crypto_shash *tfm;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ctx->tfm = tfm;
	mutex_init(&ctx->hash_lock);
	mutex_init(&ctx->launch_lock);
	init_rwsem(&ctx->users);
	init_waitqueue_head(&ctx->wq);

	return 0;
}

void sgx_le_exit(struct sgx_le_ctx *ctx)
{
	mutex_lock(&ctx->launch_lock);
	crypto_free_shash(ctx->tfm);
	mutex_unlock(&ctx->launch_lock);
}

static int __sgx_le_get_token(struct sgx_le_ctx *ctx,
			      const struct sgx_encl *encl,
			      struct sgx_einittoken *token)
{
	ssize_t ret;
	int result;

	if (!ctx->tgid)
		return -EIO;

	ctx->user_read = true;
	wake_up_interruptible(&ctx->wq);

	ret = wait_event_interruptible(ctx->wq, ctx->kernel_read);
	if (ret)
		return -EINTR;

	result = ctx->req.output.result;

	if (result == SGX_SUCCESS)
		memcpy(token, &ctx->req.output.token, sizeof(*token));

	ctx->kernel_read = false;

	return result;
}

int sgx_le_get_token(struct sgx_le_ctx *ctx,
		     const struct sgx_encl *encl,
		     const struct sgx_sigstruct *sigstruct,
		     struct sgx_einittoken *token)
{
	u8 mrsigner[32] = {0};
	int ret;

	mutex_lock(&ctx->hash_lock);
	ret = sgx_get_key_hash(ctx->tfm, sigstruct->modulus, mrsigner);
	if (ret) {
		mutex_unlock(&ctx->hash_lock);
		return ret;
	}
	if (!memcmp(mrsigner, sgx_le_pubkeyhash, 32)) {
		token->payload.valid = 0;
		mutex_unlock(&ctx->hash_lock);
		return 0;
	}
	mutex_unlock(&ctx->hash_lock);

	mutex_lock(&ctx->launch_lock);
	ret = __sgx_le_start(ctx);
	if (ret) {
		mutex_unlock(&ctx->launch_lock);
		return ret;
	}
	memcpy(&ctx->req.mrenclave, sigstruct->body.mrenclave, 32);
	memcpy(&ctx->req.mrsigner, mrsigner, 32);
	ctx->req.attributes = encl->attributes;
	ctx->req.xfrm = encl->xfrm;
	memset(&ctx->req.output, 0, sizeof(ctx->req.output));
	ret = __sgx_le_get_token(ctx, encl, token);
	mutex_unlock(&ctx->launch_lock);
	return ret;
}
