/*
 * GOST R 34.12-2015 (Kuznyechik) and GOST R 34.13-2015 (MGM)
 *
 * Copyright (c) 2018 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>
 * Optimized by Assistant.
 */

#include <crypto/algapi.h>
#include <crypto/gf128mul.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/cipher.h>
#include <crypto/kuznyechik.h>
#include <crypto/scatterwalk.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/unaligned.h>

typedef u8 uint8_t;
#include "kuztable.h"

#define KUZNYECHIK_SUBKEYS_SIZE (16 * 10)

#ifndef _CRYPTO_B128OPS_H
typedef struct
{
	__be64 a, b;
} be128;
#endif

struct crypto_kuznyechik_ctx
{
	u8 key[KUZNYECHIK_SUBKEYS_SIZE] __aligned(sizeof(u64));
};

static __always_inline void S(u8 *a, const u8 *b)
{
	a[0]  = pi[b[0]];
	a[1]  = pi[b[1]];
	a[2]  = pi[b[2]];
	a[3]  = pi[b[3]];
	a[4]  = pi[b[4]];
	a[5]  = pi[b[5]];
	a[6]  = pi[b[6]];
	a[7]  = pi[b[7]];
	a[8]  = pi[b[8]];
	a[9]  = pi[b[9]];
	a[10] = pi[b[10]];
	a[11] = pi[b[11]];
	a[12] = pi[b[12]];
	a[13] = pi[b[13]];
	a[14] = pi[b[14]];
	a[15] = pi[b[15]];
}

static __always_inline void Sinv(u8 *a, const u8 *b)
{
	a[0]  = pi_inv[b[0]];
	a[1]  = pi_inv[b[1]];
	a[2]  = pi_inv[b[2]];
	a[3]  = pi_inv[b[3]];
	a[4]  = pi_inv[b[4]];
	a[5]  = pi_inv[b[5]];
	a[6]  = pi_inv[b[6]];
	a[7]  = pi_inv[b[7]];
	a[8]  = pi_inv[b[8]];
	a[9]  = pi_inv[b[9]];
	a[10] = pi_inv[b[10]];
	a[11] = pi_inv[b[11]];
	a[12] = pi_inv[b[12]];
	a[13] = pi_inv[b[13]];
	a[14] = pi_inv[b[14]];
	a[15] = pi_inv[b[15]];
}

static __always_inline void Linv(u8 *a, const u8 *b)
{
	u8		   sb[16];
	u64		   r0, r1;
	const u64 *t;

	S(sb, b);

	t  = (const u64 *)&kuz_table_inv_LS[0][sb[0] * 16];
	r0 = t[0];
	r1 = t[1];

#define LINV_XOR(i)                                                                                                                                \
	t = (const u64 *)&kuz_table_inv_LS[i][sb[i] * 16];                                                                                             \
	r0 ^= t[0];                                                                                                                                    \
	r1 ^= t[1];

	LINV_XOR(1);
	LINV_XOR(2);
	LINV_XOR(3);
	LINV_XOR(4);
	LINV_XOR(5);
	LINV_XOR(6);
	LINV_XOR(7);
	LINV_XOR(8);
	LINV_XOR(9);
	LINV_XOR(10);
	LINV_XOR(11);
	LINV_XOR(12);
	LINV_XOR(13);
	LINV_XOR(14);
	LINV_XOR(15);

	((u64 *)a)[0] = r0;
	((u64 *)a)[1] = r1;
#undef LINV_XOR
}

static __always_inline void LSX(u8 *a, const u8 *b, const u8 *c)
{
	u64		   r0, r1;
	const u64 *t;

	t  = (const u64 *)&kuz_table[0][(b[0] ^ c[0]) * 16];
	r0 = t[0];
	r1 = t[1];

#define LSX_XOR(i)                                                                                                                                 \
	t = (const u64 *)&kuz_table[i][(b[i] ^ c[i]) * 16];                                                                                            \
	r0 ^= t[0];                                                                                                                                    \
	r1 ^= t[1];

	LSX_XOR(1);
	LSX_XOR(2);
	LSX_XOR(3);
	LSX_XOR(4);
	LSX_XOR(5);
	LSX_XOR(6);
	LSX_XOR(7);
	LSX_XOR(8);
	LSX_XOR(9);
	LSX_XOR(10);
	LSX_XOR(11);
	LSX_XOR(12);
	LSX_XOR(13);
	LSX_XOR(14);
	LSX_XOR(15);

	((u64 *)a)[0] = r0;
	((u64 *)a)[1] = r1;
#undef LSX_XOR
}

static void subkey(u8 *out, const u8 *key, unsigned int i)
{
	u8	 temp[16] __aligned(sizeof(u64));
	u64 *k1 = (u64 *)(key);
	u64 *k2 = (u64 *)(key + 16);
	u64 *o1 = (u64 *)(out);
	u64 *o2 = (u64 *)(out + 16);
	u64 *t	= (u64 *)temp;

	LSX(temp, key + 0, kuz_key_table[i + 0]);
	o2[0] = t[0] ^ k2[0];
	o2[1] = t[1] ^ k2[1];
	LSX(temp, out + 16, kuz_key_table[i + 1]);
	o1[0] = t[0] ^ k1[0];
	o1[1] = t[1] ^ k1[1];
	LSX(temp, out + 0, kuz_key_table[i + 2]);
	o2[0] ^= t[0];
	o2[1] ^= t[1];
	LSX(temp, out + 16, kuz_key_table[i + 3]);
	o1[0] ^= t[0];
	o1[1] ^= t[1];
	LSX(temp, out + 0, kuz_key_table[i + 4]);
	o2[0] ^= t[0];
	o2[1] ^= t[1];
	LSX(temp, out + 16, kuz_key_table[i + 5]);
	o1[0] ^= t[0];
	o1[1] ^= t[1];
	LSX(temp, out + 0, kuz_key_table[i + 6]);
	o2[0] ^= t[0];
	o2[1] ^= t[1];
	LSX(temp, out + 16, kuz_key_table[i + 7]);
	o1[0] ^= t[0];
	o1[1] ^= t[1];
}

static int kuznyechik_set_key(struct crypto_tfm *tfm, const u8 *in_key, unsigned int key_len)
{
	struct crypto_kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
	if (key_len != KUZNYECHIK_KEY_SIZE)
		return -EINVAL;
	memcpy(ctx->key, in_key, 32);
	subkey(ctx->key + 32, ctx->key, 0);
	subkey(ctx->key + 64, ctx->key + 32, 8);
	subkey(ctx->key + 96, ctx->key + 64, 16);
	subkey(ctx->key + 128, ctx->key + 96, 24);
	return 0;
}

static void kuznyechik_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_kuznyechik_ctx *ctx	 = crypto_tfm_ctx(tfm);
	const u64						   *keys = (const u64 *)ctx->key;
	u8									temp[KUZNYECHIK_BLOCK_SIZE] __aligned(sizeof(u64));
	u64								   *o = (u64 *)out;
	u64								   *t = (u64 *)temp;

	LSX(temp, (u8 *)(keys + 0), in);
	LSX(temp, (u8 *)(keys + 2), temp);
	LSX(temp, (u8 *)(keys + 4), temp);
	LSX(temp, (u8 *)(keys + 6), temp);
	LSX(temp, (u8 *)(keys + 8), temp);
	LSX(temp, (u8 *)(keys + 10), temp);
	LSX(temp, (u8 *)(keys + 12), temp);
	LSX(temp, (u8 *)(keys + 14), temp);
	LSX(temp, (u8 *)(keys + 16), temp);

	o[0] = t[0] ^ keys[18];
	o[1] = t[1] ^ keys[19];
}

static void kuznyechik_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_kuznyechik_ctx *ctx	 = crypto_tfm_ctx(tfm);
	const u64						   *keys = (const u64 *)ctx->key;
	u8									block[KUZNYECHIK_BLOCK_SIZE] __aligned(sizeof(u64));
	u64								   *b = (u64 *)block;
	u64								   *o = (u64 *)out;

	b[0] = ((const u64 *)in)[0] ^ keys[18];
	b[1] = ((const u64 *)in)[1] ^ keys[19];

	Linv(block, block);
	Sinv(block, block);
	b[0] ^= keys[16];
	b[1] ^= keys[17];
	Linv(block, block);
	Sinv(block, block);
	b[0] ^= keys[14];
	b[1] ^= keys[15];
	Linv(block, block);
	Sinv(block, block);
	b[0] ^= keys[12];
	b[1] ^= keys[13];
	Linv(block, block);
	Sinv(block, block);
	b[0] ^= keys[10];
	b[1] ^= keys[11];
	Linv(block, block);
	Sinv(block, block);
	b[0] ^= keys[8];
	b[1] ^= keys[9];
	Linv(block, block);
	Sinv(block, block);
	b[0] ^= keys[6];
	b[1] ^= keys[7];
	Linv(block, block);
	Sinv(block, block);
	b[0] ^= keys[4];
	b[1] ^= keys[5];
	Linv(block, block);
	Sinv(block, block);
	b[0] ^= keys[2];
	b[1] ^= keys[3];

	o[0] = b[0] ^ keys[0];
	o[1] = b[1] ^ keys[1];
}

static struct crypto_alg kuznyechik_alg = {.cra_name		= "kuznyechik",
										   .cra_driver_name = "kuznyechik-fast-generic",
										   .cra_priority	= 300,
										   .cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
										   .cra_blocksize	= KUZNYECHIK_BLOCK_SIZE,
										   .cra_ctxsize		= sizeof(struct crypto_kuznyechik_ctx),
										   .cra_module		= THIS_MODULE,
										   .cra_u.cipher	= {
												  .cia_min_keysize = KUZNYECHIK_KEY_SIZE,
												  .cia_max_keysize = KUZNYECHIK_KEY_SIZE,
												  .cia_setkey	   = kuznyechik_set_key,
												  .cia_encrypt	   = kuznyechik_encrypt,
												  .cia_decrypt	   = kuznyechik_decrypt,
											  }};

struct kuz_mgm_ctx
{
	struct crypto_cipher *child;
};

static inline struct crypto_tfm *kuz_cipher_tfm(struct crypto_cipher *tfm)
{
	return &tfm->base;
}

static inline void inc_be64(u8 *p)
{
	u64 v = get_unaligned_be64(p);
	v++;
	put_unaligned_be64(v, p);
}

static inline void inc_l(u8 *block)
{
	inc_be64(block);
}
static inline void inc_r(u8 *block)
{
	inc_be64(block + 8);
}

static inline void kuz_be128_xor(be128 *dst, const be128 *src1, const be128 *src2)
{
	dst->a = src1->a ^ src2->a;
	dst->b = src1->b ^ src2->b;
}

static int kuz_mgm_setkey(struct crypto_aead *aead, const u8 *key, unsigned int keylen)
{
	struct kuz_mgm_ctx *ctx		  = crypto_aead_ctx(aead);
	struct crypto_tfm  *child_tfm = kuz_cipher_tfm(ctx->child);
	if (keylen != KUZNYECHIK_KEY_SIZE)
		return -EINVAL;
	crypto_tfm_clear_flags(child_tfm, CRYPTO_TFM_REQ_MASK);
	crypto_tfm_set_flags(child_tfm, crypto_aead_get_flags(aead) & CRYPTO_TFM_REQ_MASK);
	return crypto_cipher_setkey(ctx->child, key, keylen);
}

static int kuz_mgm_setauthsize(struct crypto_aead *tfm, unsigned int authsize)
{
	if (authsize < 4 || authsize > 16)
		return -EINVAL;
	return 0;
}

static inline void mgm_mul_add_tag_fast(be128 *tag, const u8 *data, const be128 *h_i)
{
	be128 d_block;
	/* Optimization: Use 64-bit moves if alignment allows */
	const u64 *dp = (const u64 *)data;
	u64		  *tp = (u64 *)&d_block;
	tp[0]		  = get_unaligned(&dp[0]);
	tp[1]		  = get_unaligned(&dp[1]);

	gf128mul_x_bbe(&d_block, h_i);
	kuz_be128_xor(tag, tag, &d_block);
}

static int do_mgm_crypt(struct aead_request *req, bool encrypt)
{
	struct crypto_aead *aead	 = crypto_aead_reqtfm(req);
	struct kuz_mgm_ctx *ctx		 = crypto_aead_ctx(aead);
	unsigned int		cryptlen = req->cryptlen;
	unsigned int		assoclen = req->assoclen;
	unsigned int		authsize = crypto_aead_authsize(aead);

	u8					nonce_buf[16] __aligned(16);
	be128				h_key;
	be128				tag = {0};
	u8					buffer[16];
	u8					enc_ctr[16] __aligned(16);
	u8					auth_ctr[16] __aligned(16);
	struct scatter_walk src_walk, dst_walk;

	if (!encrypt)
	{
		if (cryptlen < authsize)
			return -EINVAL;
		cryptlen -= authsize;
	}

	memcpy(nonce_buf, req->iv, 16);
	nonce_buf[0] &= 0x7F;
	crypto_cipher_encrypt_one(ctx->child, enc_ctr, nonce_buf);

	memcpy(nonce_buf, req->iv, 16);
	nonce_buf[0] |= 0x80;
	crypto_cipher_encrypt_one(ctx->child, auth_ctr, nonce_buf);

	scatterwalk_start(&src_walk, req->src);
	scatterwalk_start(&dst_walk, req->dst);

	if (assoclen > 0)
	{
		unsigned int total = assoclen;
		while (total)
		{
			unsigned int len = min(total, 16U);

			crypto_cipher_encrypt_one(ctx->child, (u8 *)&h_key, auth_ctr);
			inc_l(auth_ctr);

			memcpy_from_scatterwalk(buffer, &src_walk, len);
			if (len < 16)
				memset(buffer + len, 0, 16 - len);

			mgm_mul_add_tag_fast(&tag, buffer, &h_key);
			total -= len;
		}
	}

	if (assoclen > 0)
		scatterwalk_skip(&dst_walk, assoclen);

	if (cryptlen > 0)
	{
		unsigned int total = cryptlen;
		u8			 keystream[16] __aligned(16);

		while (total)
		{
			unsigned int len = min(total, 16U);

			crypto_cipher_encrypt_one(ctx->child, keystream, enc_ctr);
			inc_r(enc_ctr);

			memcpy_from_scatterwalk(buffer, &src_walk, len);

			crypto_cipher_encrypt_one(ctx->child, (u8 *)&h_key, auth_ctr);
			inc_l(auth_ctr);

			if (encrypt)
			{
				u8 temp_p[16];
				memcpy(temp_p, buffer, len);
				if (len < 16)
					memset(temp_p + len, 0, 16 - len);
				mgm_mul_add_tag_fast(&tag, temp_p, &h_key);
				crypto_xor(buffer, keystream, len);
				memcpy_to_scatterwalk(&dst_walk, buffer, len);
			}
			else
			{
				crypto_xor(buffer, keystream, len);
				u8 temp_p[16];
				memcpy(temp_p, buffer, len);
				if (len < 16)
					memset(temp_p + len, 0, 16 - len);
				mgm_mul_add_tag_fast(&tag, temp_p, &h_key);
				memcpy_to_scatterwalk(&dst_walk, buffer, len);
			}
			total -= len;
		}
	}

	{
		u8 len_block[16];
		put_unaligned_be64((u64)assoclen * 8, len_block);
		put_unaligned_be64((u64)cryptlen * 8, len_block + 8);

		crypto_cipher_encrypt_one(ctx->child, (u8 *)&h_key, auth_ctr);
		mgm_mul_add_tag_fast(&tag, len_block, &h_key);
	}

	if (encrypt)
	{
		memcpy_to_scatterwalk(&dst_walk, &tag, authsize);
		return 0;
	}
	else
	{
		u8 expected_tag[16];
		memcpy_from_scatterwalk(expected_tag, &src_walk, authsize);
		if (crypto_memneq(&tag, expected_tag, authsize))
			return -EBADMSG;
		return 0;
	}
}

static int kuz_mgm_encrypt(struct aead_request *req)
{
	return do_mgm_crypt(req, true);
}
static int kuz_mgm_decrypt(struct aead_request *req)
{
	return do_mgm_crypt(req, false);
}

static int kuz_mgm_init_tfm(struct crypto_aead *tfm)
{
	struct kuz_mgm_ctx *ctx = crypto_aead_ctx(tfm);
	ctx->child				= crypto_alloc_cipher("kuznyechik-fast-generic", 0, 0);
	if (IS_ERR(ctx->child))
		return PTR_ERR(ctx->child);
	return 0;
}

static void kuz_mgm_exit_tfm(struct crypto_aead *tfm)
{
	struct kuz_mgm_ctx *ctx = crypto_aead_ctx(tfm);
	crypto_free_cipher(ctx->child);
}

static struct aead_alg kuz_mgm_alg = {.setkey	   = kuz_mgm_setkey,
									  .setauthsize = kuz_mgm_setauthsize,
									  .encrypt	   = kuz_mgm_encrypt,
									  .decrypt	   = kuz_mgm_decrypt,
									  .init		   = kuz_mgm_init_tfm,
									  .exit		   = kuz_mgm_exit_tfm,
									  .ivsize	   = KUZNYECHIK_BLOCK_SIZE,
									  .maxauthsize = KUZNYECHIK_BLOCK_SIZE,
									  .base		   = {
												 .cra_name		  = "mgm(kuznyechik)",
												 .cra_driver_name = "mgm-kuznyechik-fast-generic",
												 .cra_priority	  = 150,
												 .cra_flags		  = CRYPTO_ALG_TYPE_AEAD,
												 .cra_blocksize	  = KUZNYECHIK_BLOCK_SIZE,
												 .cra_ctxsize	  = sizeof(struct kuz_mgm_ctx),
												 .cra_module	  = THIS_MODULE,
										 }};

#ifdef DEBUG
static bool check_vector(const char *name, const u8 *actual, const u8 *expected, size_t size)
{
	if (memcmp(actual, expected, size) != 0)
	{
		pr_err("Kuznyechik-MGM Test FAILED at %s\n", name);
		print_hex_dump(KERN_ERR, "Expected: ", DUMP_PREFIX_NONE, 16, 1, expected, size, false);
		print_hex_dump(KERN_ERR, "Actual:   ", DUMP_PREFIX_NONE, 16, 1, actual, size, false);
		return false;
	}
	pr_info("Kuznyechik-MGM Test OK: %s\n", name);
	return true;
}

static void verify_gost_test_vectors(void)
{
	const u8 key[]	 = {0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
						0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
	const u8 nonce[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88};
	const u8 ad[] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04, 0x04, 0x04, 0x04, 0x04,
					 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0xEA, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05};
	const u8 plain[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x00,
						0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x11, 0x22,
						0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x22, 0x33, 0x44,
						0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11, 0xAA, 0xBB, 0xCC};

	const u8 exp_C[]   = {0xA9, 0x75, 0x7B, 0x81, 0x47, 0x95, 0x6E, 0x90, 0x55, 0xB8, 0xA3, 0x3D, 0xE8, 0x9F, 0x42, 0xFC, 0x80,
						  0x75, 0xD2, 0x21, 0x2B, 0xF9, 0xFD, 0x5B, 0xD3, 0xF7, 0x06, 0x9A, 0xAD, 0xC1, 0x6B, 0x39, 0x49, 0x7A,
						  0xB1, 0x59, 0x15, 0xA6, 0xBA, 0x85, 0x93, 0x6B, 0x5D, 0x0E, 0xA9, 0xF6, 0x85, 0x1C, 0xC6, 0x0C, 0x14,
						  0xD4, 0xD3, 0xF8, 0x83, 0xD0, 0xAB, 0x94, 0x42, 0x06, 0x95, 0xC7, 0x6D, 0xEB, 0x2C, 0x75, 0x52};
	const u8 exp_Tag[] = {0xCF, 0x5D, 0x65, 0x6F, 0x40, 0xC3, 0x4F, 0x5C, 0x46, 0xE8, 0xBB, 0x0E, 0x29, 0xFC, 0xDB, 0x4C};

	pr_info("--- Running Crypto API Test ---\n");
	{
		struct crypto_aead	*api_tfm;
		struct aead_request *api_req;
		u8					*buf = kmalloc(200, GFP_KERNEL);
		struct scatterlist	 sg[1];

		api_tfm = crypto_alloc_aead("mgm(kuznyechik)", 0, 0);
		if (!IS_ERR(api_tfm))
		{
			crypto_aead_setkey(api_tfm, key, 32);
			crypto_aead_setauthsize(api_tfm, 16);
			api_req = aead_request_alloc(api_tfm, GFP_KERNEL);

			memcpy(buf, ad, sizeof(ad));
			memcpy(buf + sizeof(ad), plain, sizeof(plain));
			sg_init_one(sg, buf, sizeof(ad) + sizeof(plain) + 16);

			aead_request_set_crypt(api_req, sg, sg, sizeof(plain), (u8 *)nonce);
			aead_request_set_ad(api_req, sizeof(ad));

			crypto_aead_encrypt(api_req);

			check_vector("API: Ciphertext", buf + sizeof(ad), exp_C, sizeof(exp_C));
			check_vector("API: Tag", buf + sizeof(ad) + sizeof(plain), exp_Tag, 16);

			aead_request_free(api_req);
			crypto_free_aead(api_tfm);
		}
		kfree(buf);
	}
}
#endif

static int __init kuznyechik_mod_init(void)
{
	int err;
	err = crypto_register_alg(&kuznyechik_alg);
	if (err)
		return err;
	err = crypto_register_aead(&kuz_mgm_alg);
	if (err)
	{
		crypto_unregister_alg(&kuznyechik_alg);
		return err;
	}

#ifdef DEBUG
	verify_gost_test_vectors();
#endif
	return 0;
}

static void __exit kuznyechik_mod_exit(void)
{
	crypto_unregister_aead(&kuz_mgm_alg);
	crypto_unregister_alg(&kuznyechik_alg);
}

module_init(kuznyechik_mod_init);
module_exit(kuznyechik_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Optimized GOST R 34.12-2015 (Kuznyechik) and MGM AEAD");
MODULE_ALIAS_CRYPTO("kuznyechik");
MODULE_ALIAS_CRYPTO("mgm(kuznyechik)");
MODULE_IMPORT_NS("CRYPTO_INTERNAL");
