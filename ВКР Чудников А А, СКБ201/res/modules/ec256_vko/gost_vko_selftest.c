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
#include "gost_vko_selftest.h"

#include "gost_curves.h"
#include "gost_math.h"

#include <crypto/hash.h>
#include <crypto/internal/ecc.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

#define pr_test(fmt, ...) pr_info("ec256-vko-test: " fmt, ##__VA_ARGS__)

#ifdef DEBUG
static int test_vli_math(void)
{
	u64 a[4] = {5}, b[4] = {7}, c[4], d[8];
	pr_test("Running VLI math tests...\n");

	vli_add(c, a, b, 4);
	if (c[0] != 12 || c[1] != 0)
	{
		pr_err("VLI add test FAILED! Got %llu\n", c[0]);
		return -EINVAL;
	}

	vli_mult(d, a, b, 4);
	if (d[0] != 35 || d[1] != 0)
	{
		pr_err("VLI mult test FAILED!\n");
		return -EINVAL;
	}

	pr_test("VLI math tests PASSED.\n");
	return 0;
}

static int test_hmac_gost(void)
{
	struct crypto_shash *tfm;
	struct shash_desc	*desc;
	int					 ret = -1;

	// Vector from Appendix A, Example 1 (HMAC_GOSTR3411_2012_256)
	const u8 key[]			 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	const u8 data[]			 = {0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00};
	const u8 expected_hmac[] = {0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
								0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9};
	u8		 result[32];

	pr_test("Running HMAC-GOST test...\n");

	tfm = crypto_alloc_shash("hmac(streebog256)", 0, 0);
	if (IS_ERR(tfm))
	{
		pr_err("Failed to load transform for hmac(streebog256): %ld. Skipping test.\n", PTR_ERR(tfm));
		return 0;
	}

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc)
	{
		ret = -ENOMEM;
		goto free_tfm;
	}
	desc->tfm = tfm;

	ret = crypto_shash_setkey(tfm, key, sizeof(key));
	if (ret)
	{
		pr_err("HMAC setkey failed\n");
		goto free_desc;
	}

	ret = crypto_shash_digest(desc, data, sizeof(data), result);
	if (ret)
	{
		pr_err("HMAC digest failed\n");
		goto free_desc;
	}

	if (memcmp(result, expected_hmac, sizeof(result)) != 0)
	{
		pr_err("HMAC test FAILED!\n");
		print_hex_dump(KERN_ERR, "Got: ", DUMP_PREFIX_NONE, 16, 1, result, sizeof(result), false);
		print_hex_dump(KERN_ERR, "Exp: ", DUMP_PREFIX_NONE, 16, 1, expected_hmac, sizeof(expected_hmac), false);
		ret = -EINVAL;
	}
	else
	{
		pr_test("HMAC-GOST test PASSED.\n");
		ret = 0;
	}

free_desc:
	kfree(desc);
free_tfm:
	crypto_free_shash(tfm);
	return ret;
}

#define NDIGITS_256 4
#define NDIGITS_512 8

static void debug_dump(const char *prefix, const u8 *data, size_t len)
{
	print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_NONE, 32, 1, data, len, false);
}

static int test_vko_256_generated(void)
{
	struct gost_vko_params	params_a, params_b;
	const struct ecc_curve *curve;
	u64					   *pub_a_x, *pub_a_y;
	u64					   *pub_b_x, *pub_b_y;
	u64					   *shared_a, *shared_b;
	u64					   *scalar_a, *scalar_b;
	u64					   *tmp_y;
	int						ret = -ENOMEM;

	curve = gost_get_curve(GOST_CURVE_256A);
	if (!curve)
	{
		pr_err("ec256-vko-test: Failed to get curve 256A\n");
		return -EINVAL;
	}

	pub_a_x	 = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);
	pub_a_y	 = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);
	pub_b_x	 = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);
	pub_b_y	 = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);
	shared_a = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);
	shared_b = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);
	scalar_a = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);
	scalar_b = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);
	tmp_y	 = kcalloc(GOST_EC256_NDIGITS, sizeof(u64), GFP_KERNEL);

	if (!pub_a_x || !pub_a_y || !pub_b_x || !pub_b_y || !shared_a || !shared_b || !scalar_a || !scalar_b || !tmp_y)
		goto out;

	pr_info("ec256-vko-test: Running VKO Generated Keys test...\n");

	/* Alice */
	do
	{
		get_random_bytes(params_a.key, sizeof(params_a.key));
	} while (gost_ec256_validate_key(params_a.key, curve) < 0);
	gost_ec256_point_mul(pub_a_x, pub_a_y, curve->g.x, curve->g.y, params_a.key, curve);

	/* Bob */
	do
	{
		get_random_bytes(params_b.key, sizeof(params_b.key));
	} while (gost_ec256_validate_key(params_b.key, curve) < 0);
	gost_ec256_point_mul(pub_b_x, pub_b_y, curve->g.x, curve->g.y, params_b.key, curve);

	/* Exchange */
	get_random_bytes(params_a.ukm, sizeof(params_a.ukm));
	memcpy(params_b.ukm, params_a.ukm, sizeof(params_b.ukm));

	/* Alice: K = (d_a * UKM * Q_b).x */
	gost_vli_mod_mult(scalar_a, params_a.key, params_a.ukm, curve->n, GOST_EC256_NDIGITS);
	gost_ec256_point_mul(shared_a, tmp_y, pub_b_x, pub_b_y, scalar_a, curve);

	/* Bob: K = (d_b * UKM * Q_a).x */
	gost_vli_mod_mult(scalar_b, params_b.key, params_b.ukm, curve->n, GOST_EC256_NDIGITS);
	gost_ec256_point_mul(shared_b, tmp_y, pub_a_x, pub_a_y, scalar_b, curve);

	if (memcmp(shared_a, shared_b, GOST_EC256_KEY_SIZE) != 0)
	{
		pr_err("ec256-vko-test: Generated keys mismatch!\n");
		ret = -EFAULT;
		goto out;
	}

	pr_info("ec256-vko-test: VKO Generated: PASSED (Keys match)\n");
	ret = 0;

out:
	kfree(pub_a_x);
	kfree(pub_a_y);
	kfree(pub_b_x);
	kfree(pub_b_y);
	kfree(shared_a);
	kfree(shared_b);
	kfree(scalar_a);
	kfree(scalar_b);
	kfree(tmp_y);
	return ret;
}

static int test_vko_512_generated(void)
{
	const struct ecc_curve *curve = gost_get_curve(GOST_CURVE_512A);

	/* Keys */
	u64 priv_a[GOST_EC256_NDIGITS];
	u64 priv_b[GOST_EC256_NDIGITS];
	u64 pub_a_x[GOST_EC256_NDIGITS], pub_a_y[GOST_EC256_NDIGITS];
	u64 pub_b_x[GOST_EC256_NDIGITS], pub_b_y[GOST_EC256_NDIGITS];
	u64 ukm[GOST_EC256_NDIGITS];

	u64 scalar[GOST_EC256_NDIGITS];
	u64 shared_x[GOST_EC256_NDIGITS], shared_y[GOST_EC256_NDIGITS];

	u8 shared_be[64];
	u8 raw_buf[64];	
	u8 dump_buf[128];

	u8 kek_a[32];
	u8 kek_b[32];

	struct crypto_shash *hash_tfm = NULL;
	struct shash_desc	*desc	  = NULL;
	int					 ret	  = 0;

	pr_test("Running VKO Generated Keys test (512-bit)...\n");

	if (!curve)
		return -EINVAL;

	hash_tfm = crypto_alloc_shash("streebog256", 0, 0);
	if (IS_ERR(hash_tfm))
		return 0;
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
	if (!desc)
	{
		crypto_free_shash(hash_tfm);
		return -ENOMEM;
	}
	desc->tfm = hash_tfm;

	get_random_bytes(raw_buf, 64);
	gost_vli_from_be(ukm, raw_buf, GOST_EC256_NDIGITS);
	debug_dump("UKM:         ", raw_buf, 64);

	/* Alice */
	do
	{
		get_random_bytes(raw_buf, 64);
		gost_vli_from_be(priv_a, raw_buf, GOST_EC256_NDIGITS);
	} while (gost_ec256_validate_key(priv_a, curve));

	gost_vli_to_be(dump_buf, priv_a, GOST_EC256_NDIGITS);
	debug_dump("Alice Priv:  ", dump_buf, 64);

	/* Q_A = d_A * G */
	gost_ec256_point_mul(pub_a_x, pub_a_y, curve->g.x, curve->g.y, priv_a, curve);

	gost_vli_to_be(dump_buf, pub_a_x, GOST_EC256_NDIGITS);
	gost_vli_to_be(dump_buf + 64, pub_a_y, GOST_EC256_NDIGITS);
	debug_dump("Alice Pub:   ", dump_buf, 128);

	/* Bob */
	do
	{
		get_random_bytes(raw_buf, 64);
		gost_vli_from_be(priv_b, raw_buf, GOST_EC256_NDIGITS);
	} while (gost_ec256_validate_key(priv_b, curve));

	gost_vli_to_be(dump_buf, priv_b, GOST_EC256_NDIGITS);
	debug_dump("Bob Priv:    ", dump_buf, 64);

	/* Q_B = d_B * G */
	gost_ec256_point_mul(pub_b_x, pub_b_y, curve->g.x, curve->g.y, priv_b, curve);

	gost_vli_to_be(dump_buf, pub_b_x, GOST_EC256_NDIGITS);
	gost_vli_to_be(dump_buf + 64, pub_b_y, GOST_EC256_NDIGITS);
	debug_dump("Bob Pub:     ", dump_buf, 128);

	/* Alice VKO: K = (UKM * d_A) * Q_B */
	gost_vli_mod_mult(scalar, ukm, priv_a, curve->n, GOST_EC256_NDIGITS);
	gost_ec256_point_mul(shared_x, shared_y, pub_b_x, pub_b_y, scalar, curve);

	gost_vli_to_be(shared_be, shared_x, GOST_EC256_NDIGITS);
	crypto_shash_digest(desc, shared_be, 64, kek_a);

	/* Bob VKO: K = (UKM * d_B) * Q_A */
	gost_vli_mod_mult(scalar, ukm, priv_b, curve->n, GOST_EC256_NDIGITS);
	gost_ec256_point_mul(shared_x, shared_y, pub_a_x, pub_a_y, scalar, curve);

	gost_vli_to_be(shared_be, shared_x, GOST_EC256_NDIGITS);
	crypto_shash_digest(desc, shared_be, 64, kek_b);

	debug_dump("KEK A:       ", kek_a, 32);
	debug_dump("KEK B:       ", kek_b, 32);

	if (memcmp(kek_a, kek_b, 32) == 0)
	{
		pr_info("VKO Generated: PASSED (Keys match)\n");
	}
	else
	{
		pr_err("VKO Generated: FAILED (Keys mismatch)\n");
		ret = -EINVAL;
	}

	kfree(desc);
	crypto_free_shash(hash_tfm);
	return ret;
}
#endif

int gost_kpp_run_tests(void)
{
	int ret;
#ifdef DEBUG
	ret = test_vli_math();
	if (ret)
		return ret;

	ret = test_hmac_gost();
	if (ret)
		return ret;

	ret = test_vko_512_generated();
	if (ret)
		return ret;

	pr_info("gost_kpp: All self-tests passed.\n");
#endif
	return 0;
}
