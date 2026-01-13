/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */

#include "gost_kuznyechik.h"

#include <crypto/algapi.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/cipher.h>
#include <crypto/scatterwalk.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/slab.h>

static int do_aead_op(struct crypto_aead *tfm, u8 *dst, const u8 *src, size_t len, const u8 *ad, size_t ad_len, const u8 *nonce, bool encrypt)
{
	struct aead_request *req;
	struct scatterlist	 sg_src[2], sg_dst[2];
	int					 ret;

	req = aead_request_alloc(tfm, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	if (ad_len > 0)
	{
		sg_init_table(sg_src, 2);
		sg_set_buf(&sg_src[0], ad, ad_len);
		sg_set_buf(&sg_src[1], src, len);

		sg_init_table(sg_dst, 2);
		sg_set_buf(&sg_dst[0], ad, ad_len);
		sg_set_buf(&sg_dst[1], dst, len + (encrypt ? KUZNYECHIK_MGM_TAG_SIZE : 0));

		aead_request_set_crypt(req, sg_src, sg_dst, len, (u8 *)nonce);
		aead_request_set_ad(req, ad_len);
	}
	else
	{
		sg_init_one(sg_src, src, len);
		sg_init_one(sg_dst, dst, len + (encrypt ? KUZNYECHIK_MGM_TAG_SIZE : 0));

		aead_request_set_crypt(req, sg_src, sg_dst, len, (u8 *)nonce);
		aead_request_set_ad(req, 0);
	}

	if (encrypt)
		ret = crypto_aead_encrypt(req);
	else
		ret = crypto_aead_decrypt(req);

	aead_request_free(req);
	return ret;
}

void gost_kuznyechik_mgm_free_ctx(struct gost_kuznyechik_mgm_ctx *ctx)
{
	if (ctx && ctx->tfm)
	{
		crypto_free_aead(ctx->tfm);
		ctx->tfm = NULL;
	}
}

int gost_kuznyechik_mgm_set_key(struct gost_kuznyechik_mgm_ctx *ctx, const u8 *key)
{
	if (!ctx->tfm)
	{
		ctx->tfm = crypto_alloc_aead("mgm(kuznyechik)", 0, 0);
		if (IS_ERR(ctx->tfm))
		{
			int err	 = PTR_ERR(ctx->tfm);
			ctx->tfm = NULL;
			return err;
		}

		if (crypto_aead_setauthsize(ctx->tfm, KUZNYECHIK_MGM_TAG_SIZE))
		{
			crypto_free_aead(ctx->tfm);
			ctx->tfm = NULL;
			return -EINVAL;
		}
	}

	return crypto_aead_setkey(ctx->tfm, key, KUZNYECHIK_KEY_SIZE);
}

int gost_kuznyechik_mgm_encrypt(struct gost_kuznyechik_mgm_ctx *ctx,
								u8							   *dst,
								const u8					   *src,
								size_t							src_len,
								const u8					   *ad,
								size_t							ad_len,
								const u8					   *nonce)
{
	if (unlikely(!ctx->tfm))
		return -EINVAL;
	return do_aead_op(ctx->tfm, dst, src, src_len, ad, ad_len, nonce, true);
}

int gost_kuznyechik_mgm_decrypt(struct gost_kuznyechik_mgm_ctx *ctx,
								u8							   *dst,
								const u8					   *src,
								size_t							src_len,
								const u8					   *ad,
								size_t							ad_len,
								const u8					   *nonce)
{
	if (unlikely(!ctx->tfm))
		return -EINVAL;

	if (src_len < KUZNYECHIK_MGM_TAG_SIZE)
		return -EINVAL;

	return do_aead_op(ctx->tfm, dst, src, src_len, ad, ad_len, nonce, false);
}

int gost_kuznyechik_set_key(struct gost_kuznyechik_ctx *ctx, const u8 *key)
{
	if (!ctx->tfm)
	{
		ctx->tfm = crypto_alloc_cipher("kuznyechik-generic", 0, 0);
		if (IS_ERR(ctx->tfm))
		{
			int err	 = PTR_ERR(ctx->tfm);
			ctx->tfm = NULL;
			return err;
		}
	}
	return crypto_cipher_setkey(ctx->tfm, key, KUZNYECHIK_KEY_SIZE);
}

void gost_kuznyechik_encrypt_block(struct gost_kuznyechik_ctx *ctx, u8 *out, const u8 *in)
{
	if (ctx->tfm)
		crypto_cipher_encrypt_one(ctx->tfm, out, in);
}

void gost_kuznyechik_decrypt_block(struct gost_kuznyechik_ctx *ctx, u8 *out, const u8 *in)
{
	if (ctx->tfm)
		crypto_cipher_decrypt_one(ctx->tfm, out, in);
}

void gost_kuznyechik_free_ctx(struct gost_kuznyechik_ctx *ctx)
{
	if (ctx && ctx->tfm)
	{
		crypto_free_cipher(ctx->tfm);
		ctx->tfm = NULL;
	}
}

int gost_kuznyechik_init_tfms(void)
{
	return 0;
}

void gost_kuznyechik_uninit_tfms(void)
{}
