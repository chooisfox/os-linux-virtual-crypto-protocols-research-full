/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */
#ifndef _GOST_HMAC_H
#define _GOST_HMAC_H

#include <linux/types.h>

void gost_hmac256(u8 *out, const u8 *in, size_t inlen, const u8 *key, size_t keylen);

#endif /* _GOST_HMAC_H */
