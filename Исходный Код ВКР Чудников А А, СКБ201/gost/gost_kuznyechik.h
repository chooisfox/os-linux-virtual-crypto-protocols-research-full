/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */
#ifndef _GOST_KUZNYECHIK_H
#define _GOST_KUZNYECHIK_H

#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/types.h>

#define KUZNYECHIK_KEY_SIZE 32
#define KUZNYECHIK_BLOCK_SIZE 16
#define KUZNYECHIK_MGM_IV_SIZE 16
#define KUZNYECHIK_MGM_TAG_SIZE 16

struct gost_kuznyechik_ctx {
	struct crypto_cipher *tfm;
};

struct gost_kuznyechik_mgm_ctx {
	struct crypto_aead *tfm;
};

int gost_kuznyechik_init_tfms(void);
void gost_kuznyechik_uninit_tfms(void);

int gost_kuznyechik_set_key(struct gost_kuznyechik_ctx *ctx, const u8 *key);
void gost_kuznyechik_encrypt_block(struct gost_kuznyechik_ctx *ctx, u8 *out, const u8 *in);
void gost_kuznyechik_decrypt_block(struct gost_kuznyechik_ctx *ctx, u8 *out, const u8 *in);
void gost_kuznyechik_free_ctx(struct gost_kuznyechik_ctx *ctx);

int gost_kuznyechik_mgm_set_key(struct gost_kuznyechik_mgm_ctx *ctx, const u8 *key);

int gost_kuznyechik_mgm_encrypt(struct gost_kuznyechik_mgm_ctx *ctx, u8 *dst, const u8 *src, size_t src_len, const u8 *ad, size_t ad_len,
								const u8 *nonce);

int gost_kuznyechik_mgm_decrypt(struct gost_kuznyechik_mgm_ctx *ctx, u8 *dst, const u8 *src, size_t src_len, const u8 *ad, size_t ad_len,
								const u8 *nonce);
void gost_kuznyechik_mgm_free_ctx(struct gost_kuznyechik_mgm_ctx *ctx);

#endif /* _GOST_KUZNYECHIK_H */
