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
#ifndef _CRYPTO_GOST_CURVES_H
#define _CRYPTO_GOST_CURVES_H

#include <linux/kernel.h>
#include <linux/math.h>

#include <crypto/internal/ecc.h>

#define GOST_CURVE_256A 101
#define GOST_CURVE_512A 102

void gost_curves_init(void);

const struct ecc_curve *gost_get_curve(unsigned int curve_id);

#endif
