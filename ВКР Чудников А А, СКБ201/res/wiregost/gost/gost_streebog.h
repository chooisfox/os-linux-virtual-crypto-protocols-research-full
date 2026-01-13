/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */
#ifndef _GOST_STREEBOG_H
#define _GOST_STREEBOG_H

#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/types.h>

#define GOST_STREEBOG_CTX_SIZE 321
#define STREEBOG256_DIGEST_SIZE 32
#define STREEBOG_BLOCK_SIZE 64

struct gost_streebog_state {
	struct shash_desc desc;
	char ctx[GOST_STREEBOG_CTX_SIZE];
};

int gost_streebog_init_module(void);
void gost_streebog_cleanup_module(void);

void gost_streebog256_init(struct gost_streebog_state *ctx);
void gost_streebog256_update(struct gost_streebog_state *ctx, const u8 *data, size_t len);
void gost_streebog256_final(struct gost_streebog_state *ctx, u8 *hash);
void gost_streebog256(u8 *out, const u8 *in, size_t len);

#endif /* _GOST_STREEBOG_H */
