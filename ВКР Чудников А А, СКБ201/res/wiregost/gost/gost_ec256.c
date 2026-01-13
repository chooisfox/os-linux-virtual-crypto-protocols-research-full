/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */

#include "gost_ec256.h"

#include <crypto/kpp.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

struct gost_vko_packed
{
	struct kpp_secret base;
	unsigned int	  key_len;
	u8				  key[GOST_EC256_KEY_LEN];
	unsigned int	  ukm_len;
	u8				  ukm[];
} __packed;

static struct crypto_kpp *ec256_tfm = NULL;
static DEFINE_MUTEX(ec256_mutex);

int gost_ec256_init_module(void)
{
	ec256_tfm = crypto_alloc_kpp("ec256-vko", 0, 0);
	if (IS_ERR(ec256_tfm))
	{
		int err = PTR_ERR(ec256_tfm);
		pr_err("WireGost: failed to allocate ec256-vko: %d\n", err);
		ec256_tfm = NULL;
		return err;
	}
	return 0;
}

void gost_ec256_cleanup_module(void)
{
	if (ec256_tfm)
	{
		crypto_free_kpp(ec256_tfm);
		ec256_tfm = NULL;
	}
}

static int set_secret_helper(const u8 *private_key, const u8 *ukm, unsigned int ukm_len)
{
	struct gost_vko_packed *packed;
	size_t					alloc_size;
	int						err;

	alloc_size = sizeof(struct gost_vko_packed) + ukm_len;

	packed = kzalloc(alloc_size, GFP_KERNEL);
	if (!packed)
		return -ENOMEM;

	packed->base.type = CRYPTO_KPP_SECRET_TYPE_ECDH;
	packed->base.len  = alloc_size;

	packed->key_len = GOST_EC256_KEY_LEN;
	memcpy(packed->key, private_key, GOST_EC256_KEY_LEN);

	packed->ukm_len = ukm_len;
	if (ukm && ukm_len > 0)
		memcpy(packed->ukm, ukm, ukm_len);

	err = crypto_kpp_set_secret(ec256_tfm, (void *)packed, alloc_size);

	kfree(packed);
	return err;
}

bool gost_ec256_generate_private_key(u8 *private_key_out)
{
	int err;

	if (unlikely(!ec256_tfm))
		return false;

	mutex_lock(&ec256_mutex);

	do
	{
		get_random_bytes(private_key_out, GOST_EC256_KEY_LEN);
		err = set_secret_helper(private_key_out, NULL, 0);
	} while (err != 0);

	mutex_unlock(&ec256_mutex);
	return true;
}

bool gost_ec256_generate_public_key(u8 *public_key_out, const u8 *private_key)
{
	struct kpp_request *req;
	struct scatterlist	dst;
	int					err = -EINVAL;

	if (unlikely(!ec256_tfm))
		return false;

	mutex_lock(&ec256_mutex);

	req = kpp_request_alloc(ec256_tfm, GFP_KERNEL);
	if (!req)
	{
		err = -ENOMEM;
		goto out_unlock;
	}

	err = set_secret_helper(private_key, NULL, 0);
	if (err)
		goto out_free;

	sg_init_one(&dst, public_key_out, GOST_EC256_PUB_LEN);
	kpp_request_set_input(req, NULL, 0);
	kpp_request_set_output(req, &dst, GOST_EC256_PUB_LEN);

	err = crypto_kpp_generate_public_key(req);

out_free:
	kpp_request_free(req);
out_unlock:
	mutex_unlock(&ec256_mutex);
	return err == 0;
}

bool gost_ec256_dh(u8 *shared_secret, const u8 *private_key, const u8 *peer_public_key, const u8 *ukm, unsigned int ukm_len)
{
	struct kpp_request *req;
	struct scatterlist	src, dst;
	int					err = -EINVAL;

	if (unlikely(!ec256_tfm))
		return false;

	mutex_lock(&ec256_mutex);

	req = kpp_request_alloc(ec256_tfm, GFP_KERNEL);
	if (!req)
	{
		err = -ENOMEM;
		goto out_unlock;
	}

	err = set_secret_helper(private_key, ukm, ukm_len);
	if (err)
		goto out_free;

	sg_init_one(&src, peer_public_key, GOST_EC256_PUB_LEN);
	sg_init_one(&dst, shared_secret, 32);

	kpp_request_set_input(req, &src, GOST_EC256_PUB_LEN);
	kpp_request_set_output(req, &dst, 32);

	err = crypto_kpp_compute_shared_secret(req);

out_free:
	kpp_request_free(req);
out_unlock:
	mutex_unlock(&ec256_mutex);
	return err == 0;
}
