/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */
#ifndef _GOST_EC256_H_
#define _GOST_EC256_H_

#include <linux/types.h>

#define GOST_EC256_KEY_LEN 64
#define GOST_EC256_PUB_LEN 128

int gost_ec256_init_module(void);
void gost_ec256_cleanup_module(void);

bool gost_ec256_generate_private_key(u8 *private_key_out);
bool gost_ec256_generate_public_key(u8 *public_key_out, const u8 *private_key);

bool gost_ec256_dh(u8 *shared_secret, const u8 *private_key, const u8 *peer_public_key, const u8 *ukm, unsigned int ukm_len);

#endif /* _GOST_EC256_H_ */
