// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */

#include "../gost/gost_ec256.h"
#include "../gost/gost_kuznyechik.h"
#include "../gost/gost_streebog.h"

#ifdef DEBUG
#define RUN_TEST(name, func)                                                                                                                       \
	do                                                                                                                                             \
	{                                                                                                                                              \
		pr_info("Testing " name "... ");                                                                                                           \
		if (func())                                                                                                                                \
			pr_cont("PASSED\n");                                                                                                                   \
		else                                                                                                                                       \
		{                                                                                                                                          \
			pr_cont("FAILED\n");                                                                                                                   \
			ret = -EFAULT;                                                                                                                         \
			goto err_tests;                                                                                                                        \
		}                                                                                                                                          \
	} while (0)

static bool self_test_streebog(void)
{
	u8			digest[32];
	const char *msg			 = "012345678901234567890123456789012345678901234567890123456789012";
	const u8	expected[32] = {0x9d, 0x15, 0x1e, 0xef, 0xd8, 0x59, 0x0b, 0x89, 0xda, 0xa6, 0xba, 0x6c, 0xb7, 0x4a, 0xf9, 0x27,
								0x5d, 0xd0, 0x51, 0x02, 0x6b, 0xb1, 0x49, 0xa4, 0x52, 0xfd, 0x84, 0xe5, 0xe5, 0x7b, 0x55, 0x00};

	gost_streebog256(digest, (u8 *)msg, 63);

	if (memcmp(digest, expected, 32) != 0)
	{
		pr_err("Streebog-256 digest mismatch\n");
		return false;
	}
	return true;
}

static bool self_test_hmac_streebog(void)
{
	u8		   mac[32];
	const u8   key[32]		= {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	const char msg[]		= {0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00};
	const u8   expected[32] = {0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
							   0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9};

	gost_hmac256(mac, (u8 *)msg, sizeof(msg), key, 32);

	if (memcmp(mac, expected, 32) != 0)
	{
		pr_err("HMAC-Streebog-256 mismatch\n");
		return false;
	}
	return true;
}

static bool self_test_kuznyechik_mgm(void)
{
	const u8 key[32]   = {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
						  0xFE, 0xDC, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xCD, 0xEF};
	const u8 nonce[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xee, 0xDD, 0xcc, 0xbb, 0xaa, 0x99, 0x88};
	const u8 plain[67] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xee, 0xDD, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x00,
						  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xFF, 0x0a, 0x11, 0x22,
						  0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xFF, 0x0A, 0x00, 0x22, 0x33, 0x44,
						  0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xFF, 0x0a, 0x00, 0x11, 0xaa, 0xbb, 0xcc};
	u8		 ad[41] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04, 0x04, 0x04, 0x04, 0x04,
					   0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05};

	u8 cipher[100];
	u8 decrypted[100];

	struct gost_kuznyechik_mgm_ctx ctx;
	bool						   success = false;

	memset(&ctx, 0, sizeof(ctx));
	if (gost_kuznyechik_mgm_set_key(&ctx, key) != 0)
	{
		pr_err("Kuznyechik-MGM set_key failed\n");
		goto out;
	}

	/* Print Plaintext*/
	print_hex_dump(KERN_INFO, "MGM Plaintext:  ", DUMP_PREFIX_NONE, 16, 1, plain, sizeof(plain), false);

	if (gost_kuznyechik_mgm_encrypt(&ctx, cipher, plain, sizeof(plain), ad, sizeof(ad), nonce) != 0)
	{
		pr_err("Kuznyechik-MGM encryption failed\n");
		goto out;
	}

	/* Print Ciphertext: 67 data + 16 tag = 83 bytes */
	print_hex_dump(KERN_INFO, "MGM Ciphertext: ", DUMP_PREFIX_NONE, 16, 1, cipher, sizeof(plain) + 16, false);

	if (memcmp(cipher, plain, sizeof(plain)) == 0)
	{
		pr_err("Kuznyechik-MGM CRITICAL: Ciphertext matches Plaintext! (Data was not encrypted)\n");
		goto out;
	}

	/* Decrypt: Input size is Plaintext + 16 (Tag) */
	if (gost_kuznyechik_mgm_decrypt(&ctx, decrypted, cipher, sizeof(plain) + 16, ad, sizeof(ad), nonce) != 0)
	{
		pr_err("Kuznyechik-MGM decryption failed\n");
		goto out;
	}

	print_hex_dump(KERN_INFO, "MGM Decrypted:  ", DUMP_PREFIX_NONE, 16, 1, decrypted, sizeof(plain), false);

	if (memcmp(decrypted, plain, sizeof(plain)) != 0)
	{
		pr_err("Kuznyechik-MGM content mismatch after decryption\n");
		goto out;
	}

	success = true;
	pr_info("Kuznyechik-MGM self-test passed\n");

out:
	gost_kuznyechik_mgm_free_ctx(&ctx);
	return success;
}

static bool self_test_gost_vko_generated(void)
{
	u8	*priv_a, *pub_a, *kek_a;
	u8	*priv_b, *pub_b, *kek_b;
	u8	 ukm[8];
	bool success = false;

	/*
	 * Allocations now use the 512-bit constants defined in gost_ec256.h:
	 * GOST_EC256_KEY_LEN = 64
	 * GOST_EC256_PUB_LEN = 128
	 */
	priv_a = kmalloc(GOST_EC256_KEY_LEN, GFP_KERNEL);
	pub_a  = kmalloc(GOST_EC256_PUB_LEN, GFP_KERNEL);
	kek_a  = kmalloc(32, GFP_KERNEL);
	priv_b = kmalloc(GOST_EC256_KEY_LEN, GFP_KERNEL);
	pub_b  = kmalloc(GOST_EC256_PUB_LEN, GFP_KERNEL);
	kek_b  = kmalloc(32, GFP_KERNEL);

	if (!priv_a || !pub_a || !kek_a || !priv_b || !pub_b || !kek_b)
	{
		pr_err("FAIL: Memory allocation failed for VKO test\n");
		goto out_free;
	}

	get_random_bytes(ukm, 8);

	/* Alice */
	if (!gost_ec256_generate_private_key(priv_a))
	{
		pr_err("FAIL: Alice Private Key Generation failed\n");
		goto out_free;
	}
	if (!gost_ec256_generate_public_key(pub_a, priv_a))
	{
		pr_err("FAIL: Alice Public Key Generation failed\n");
		goto out_free;
	}

	/* Bob */
	if (!gost_ec256_generate_private_key(priv_b))
	{
		pr_err("FAIL: Bob Private Key Generation failed\n");
		goto out_free;
	}
	if (!gost_ec256_generate_public_key(pub_b, priv_b))
	{
		pr_err("FAIL: Bob Public Key Generation failed\n");
		goto out_free;
	}

	/* Alice computes shared key */
	if (!gost_ec256_dh(kek_a, priv_a, pub_b, ukm, 8))
	{
		pr_err("FAIL: Alice VKO calculation failed\n");
		goto out_free;
	}

	/* Bob computes shared key */
	if (!gost_ec256_dh(kek_b, priv_b, pub_a, ukm, 8))
	{
		pr_err("FAIL: Bob VKO calculation failed\n");
		goto out_free;
	}

	if (memcmp(kek_a, kek_b, 32) != 0)
	{
		pr_err("FAIL: Shared keys DO NOT MATCH!\n");
		goto out_free;
	}

	success = true;

out_free:
	kfree(priv_a);
	kfree(pub_a);
	kfree(kek_a);
	kfree(priv_b);
	kfree(pub_b);
	kfree(kek_b);
	return success;
}

#endif
