/*
 * GOST 34.10-2012 (VKO) kpp.
 *
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */
#include "gost_curves.h"
#include "gost_math.h"
#include "gost_vko_selftest.h"

#include <crypto/hash.h>
#include <crypto/internal/kpp.h>
#include <crypto/kpp.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#define DRV_NAME	"ec256-vko"
#define DRV_GENERIC "ec256-vko-generic"

struct gost_vko_ctx
{
	const struct ecc_curve *curve;
	struct gost_vko_params	params;
	bool					has_key;
};

static inline struct gost_vko_ctx *gost_vko_get_ctx(struct crypto_kpp *tfm)
{
	return kpp_tfm_ctx(tfm);
}

static int gost_vko_set_secret(struct crypto_kpp *tfm, const void *buf, unsigned int len)
{
	struct gost_vko_ctx *ctx = gost_vko_get_ctx(tfm);
	int					 ret;

	ret = gost_vko_decode_key(buf, len, &ctx->params);
	if (ret)
		return ret;

	if (gost_ec256_validate_key(ctx->params.key, ctx->curve) < 0)
	{
		memzero_explicit(ctx->params.key, sizeof(ctx->params.key));
		ctx->has_key = false;
		return -EINVAL;
	}

	ctx->has_key = true;
	return 0;
}

static int gost_vko_compute_value(struct kpp_request *req)
{
	struct crypto_kpp	*tfm = crypto_kpp_reqtfm(req);
	struct gost_vko_ctx *ctx = gost_vko_get_ctx(tfm);

	u64 *public_key_buf	 = NULL;
	u64 *shared_secret_x = NULL;

	u8	  *result_buf = NULL;
	size_t result_sz  = 0;

	int ret = -ENOMEM;
	u64 scalar[GOST_EC256_NDIGITS];

	if (!ctx->has_key)
		return -EINVAL;

	public_key_buf = kmalloc(GOST_EC256_POINT_SIZE, GFP_KERNEL);
	if (!public_key_buf)
		return -ENOMEM;

	if (req->src)
	{
		/* K = ((d * UKM) mod n) * Q_peer */

		u8 raw_peer_key[GOST_EC256_POINT_SIZE];

		if (req->src_len != GOST_EC256_POINT_SIZE)
		{
			ret = -EINVAL;
			goto free_all;
		}

		sg_copy_to_buffer(req->src, sg_nents_for_len(req->src, GOST_EC256_POINT_SIZE), raw_peer_key, GOST_EC256_POINT_SIZE);

		gost_vli_from_be(public_key_buf, raw_peer_key, GOST_EC256_NDIGITS);
		gost_vli_from_be(public_key_buf + GOST_EC256_NDIGITS, raw_peer_key + GOST_EC256_KEY_SIZE, GOST_EC256_NDIGITS);

		/* S = (d * UKM) mod n */
		if (ctx->params.ukm_size == 0)
		{
			memcpy(scalar, ctx->params.key, sizeof(scalar));
		}
		else
		{
			gost_vli_mod_mult(scalar, ctx->params.key, ctx->params.ukm, ctx->curve->n, GOST_EC256_NDIGITS);
		}

		/* K = S * Q_peer */
		shared_secret_x = kmalloc(GOST_EC256_KEY_SIZE, GFP_KERNEL);
		if (!shared_secret_x)
			goto free_all;

		gost_ec256_point_mul(shared_secret_x, public_key_buf + GOST_EC256_NDIGITS, public_key_buf, public_key_buf + GOST_EC256_NDIGITS, scalar,
							 ctx->curve);

		/* VKO KEK = Hash(K.x) */
		{
			struct crypto_shash *hash_tfm;
			struct shash_desc	*desc;
			u8					 be_x[GOST_EC256_KEY_SIZE];

			/* Encode K.x back to BE */
			gost_vli_to_be(be_x, shared_secret_x, GOST_EC256_NDIGITS);

			hash_tfm = crypto_alloc_shash("streebog256", 0, 0);
			if (IS_ERR(hash_tfm))
			{
				ret = PTR_ERR(hash_tfm);
				goto free_all;
			}

			desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
			if (!desc)
			{
				crypto_free_shash(hash_tfm);
				ret = -ENOMEM;
				goto free_all;
			}
			desc->tfm = hash_tfm;

			ret = crypto_shash_digest(desc, be_x, GOST_EC256_KEY_SIZE, be_x);

			kfree(desc);
			crypto_free_shash(hash_tfm);

			if (ret)
				goto free_all;

			memcpy(shared_secret_x, be_x, 32);
		}

		result_buf = (u8 *)shared_secret_x;
		result_sz  = 32;
	}
	else
	{
		/* Q = d * G */
		gost_ec256_point_mul(public_key_buf, public_key_buf + GOST_EC256_NDIGITS, ctx->curve->g.x, ctx->curve->g.y, ctx->params.key, ctx->curve);

		{
			u8 out_tmp[GOST_EC256_POINT_SIZE];

			gost_vli_to_be(out_tmp, public_key_buf, GOST_EC256_NDIGITS);
			gost_vli_to_be(out_tmp + GOST_EC256_KEY_SIZE, public_key_buf + GOST_EC256_NDIGITS, GOST_EC256_NDIGITS);

			memcpy(public_key_buf, out_tmp, GOST_EC256_POINT_SIZE);
		}

		result_buf = (u8 *)public_key_buf;
		result_sz  = GOST_EC256_POINT_SIZE;
	}

	if (req->dst_len < result_sz)
	{
		ret = -EINVAL;
		goto free_all;
	}

	if (sg_copy_from_buffer(req->dst, sg_nents_for_len(req->dst, result_sz), result_buf, result_sz) != result_sz)
		ret = -EINVAL;

	ret = 0;

free_all:
	kfree_sensitive(shared_secret_x);
	kfree(public_key_buf);
	return ret;
}

static unsigned int gost_vko_max_size(struct crypto_kpp *tfm)
{
	return GOST_EC256_POINT_SIZE;
}

static int gost_vko_init_tfm(struct crypto_kpp *tfm)
{
	struct gost_vko_ctx *ctx = gost_vko_get_ctx(tfm);

	ctx->curve = gost_get_curve(GOST_CURVE_512A);
	if (!ctx->curve)
		return -EINVAL;
	return 0;
}

static void gost_vko_exit_tfm(struct crypto_kpp *tfm)
{
	struct gost_vko_ctx *ctx = gost_vko_get_ctx(tfm);
	memzero_explicit(&ctx->params, sizeof(ctx->params));
}

static struct kpp_alg gost_vko_alg = {
	.set_secret			   = gost_vko_set_secret,
	.generate_public_key   = gost_vko_compute_value,
	.compute_shared_secret = gost_vko_compute_value,
	.max_size			   = gost_vko_max_size,
	.init				   = gost_vko_init_tfm,
	.exit				   = gost_vko_exit_tfm,
	.base =
		{
			.cra_name		 = DRV_NAME,
			.cra_driver_name = DRV_GENERIC,
			.cra_priority	 = 100,
			.cra_module		 = THIS_MODULE,
			.cra_ctxsize	 = sizeof(struct gost_vko_ctx),
		},
};

static int __init gost_vko_init(void)
{
	int ret;
#ifdef DEBUG
	ret = gost_kpp_run_tests();
	if (ret)
		return ret;
#endif

	return crypto_register_kpp(&gost_vko_alg);
}

static void __exit gost_vko_exit(void)
{
	crypto_unregister_kpp(&gost_vko_alg);
}

module_init(gost_vko_init);
module_exit(gost_vko_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GOST R 34.10-2012 (EC512) VKO");
MODULE_ALIAS_CRYPTO(DRV_NAME);
