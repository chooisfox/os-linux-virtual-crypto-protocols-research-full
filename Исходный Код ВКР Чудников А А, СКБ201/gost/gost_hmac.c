/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */
#include "gost_hmac.h"

#include "gost_streebog.h"

#include <crypto/utils.h>
#include <linux/string.h>

void gost_hmac256(u8 *out, const u8 *in, size_t inlen, const u8 *key, size_t keylen)
{
	struct gost_streebog_state state;
	u8						   x_key[STREEBOG_BLOCK_SIZE];
	u8						   i_hash[STREEBOG256_DIGEST_SIZE];
	int						   i;

	if (keylen > STREEBOG_BLOCK_SIZE)
	{
		gost_streebog256(x_key, key, keylen);
		memset(x_key + STREEBOG256_DIGEST_SIZE, 0, STREEBOG_BLOCK_SIZE - STREEBOG256_DIGEST_SIZE);
	}
	else
	{
		memcpy(x_key, key, keylen);
		if (keylen < STREEBOG_BLOCK_SIZE)
			memset(x_key + keylen, 0, STREEBOG_BLOCK_SIZE - keylen);
	}

	// Inner Hash = Hash((K* ^ ipad) | message)
	u8 pad_key[STREEBOG_BLOCK_SIZE];

	for (i = 0; i < STREEBOG_BLOCK_SIZE; ++i)
		pad_key[i] = x_key[i] ^ 0x36;

	gost_streebog256_init(&state);
	gost_streebog256_update(&state, pad_key, STREEBOG_BLOCK_SIZE);
	gost_streebog256_update(&state, in, inlen);
	gost_streebog256_final(&state, i_hash);

	// Outer Hash = Hash((K* ^ opad) | Inner Hash)
	for (i = 0; i < STREEBOG_BLOCK_SIZE; ++i)
		pad_key[i] = x_key[i] ^ 0x5c;

	gost_streebog256_init(&state);
	gost_streebog256_update(&state, pad_key, STREEBOG_BLOCK_SIZE);
	gost_streebog256_update(&state, i_hash, STREEBOG256_DIGEST_SIZE);
	gost_streebog256_final(&state, out);

	memzero_explicit(x_key, sizeof(x_key));
	memzero_explicit(pad_key, sizeof(pad_key));
	memzero_explicit(i_hash, sizeof(i_hash));
}
