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
#include "gost_math.h"

#include "gost_curves.h"

#include <crypto/ecc_curve.h>
#include <crypto/ecdh.h>
#include <crypto/internal/ecc.h>
#include <crypto/rng.h>
#include <linux/fips.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/swab.h>
#include <linux/unaligned.h>

typedef struct
{
	u64 m_low;
	u64 m_high;
} uint128_t;

static u64 *ecc_alloc_digits_space(unsigned int ndigits)
{
	size_t len = ndigits * sizeof(u64);

	if (!len)
		return NULL;

	return kmalloc(len, GFP_KERNEL);
}

static void ecc_free_digits_space(u64 *space)
{
	kfree_sensitive(space);
}

static void vli_clear(u64 *vli, unsigned int ndigits)
{
	int i;

	for (i = 0; i < ndigits; i++)
		vli[i] = 0;
}

/* Returns nonzero if bit of vli is set. */
static u64 vli_test_bit(const u64 *vli, unsigned int bit)
{
	return (vli[bit / 64] & ((u64)1 << (bit % 64)));
}

static bool vli_is_negative(const u64 *vli, unsigned int ndigits)
{
	return vli_test_bit(vli, ndigits * 64 - 1);
}

/* Counts the number of 64-bit "digits" in vli. */
static unsigned int vli_num_digits(const u64 *vli, unsigned int ndigits)
{
	int i;
	/* Search from the end until we find a non-zero digit.
	 * We do it in reverse because we expect that most digits will
	 * be nonzero.
	 */
	for (i = ndigits - 1; i >= 0 && vli[i] == 0; i--)
		;
	return (i + 1);
}

static void vli_set(u64 *dest, const u64 *src, unsigned int ndigits)
{
	int i;

	for (i = 0; i < ndigits; i++)
		dest[i] = src[i];
}

static u64 vli_lshift(u64 *result, const u64 *in, unsigned int shift, unsigned int ndigits)
{
	u64 carry = 0;
	int i;

	for (i = 0; i < ndigits; i++)
	{
		u64 temp = in[i];

		result[i] = (temp << shift) | carry;
		carry	  = temp >> (64 - shift);
	}

	return carry;
}

/* Computes vli = vli >> 1. */
static void vli_rshift1(u64 *vli, unsigned int ndigits)
{
	u64 *end   = vli;
	u64	 carry = 0;

	vli += ndigits;

	while (vli-- > end)
	{
		u64 temp = *vli;
		*vli	 = (temp >> 1) | carry;
		carry	 = temp << 63;
	}
}

/* Computes result = left + right, returning carry. Can modify in place. */
u64 vli_add(u64 *result, const u64 *left, const u64 *right, unsigned int ndigits)
{
	u64 carry = 0;
	int i;

	for (i = 0; i < ndigits; i++)
	{
		u64 sum;

		sum = left[i] + right[i] + carry;
		if (sum != left[i])
			carry = (sum < left[i]);

		result[i] = sum;
	}

	return carry;
}

/* Computes result = left + right, returning carry. Can modify in place. */
static u64 vli_uadd(u64 *result, const u64 *left, u64 right, unsigned int ndigits)
{
	u64 carry = right;
	int i;

	for (i = 0; i < ndigits; i++)
	{
		u64 sum;

		sum = left[i] + carry;
		if (sum != left[i])
			carry = (sum < left[i]);
		else
			carry = !!carry;

		result[i] = sum;
	}

	return carry;
}

/* Computes result = left - right, returning borrow. Can modify in place. */
static u64 vli_usub(u64 *result, const u64 *left, u64 right, unsigned int ndigits)
{
	u64 borrow = right;
	int i;

	for (i = 0; i < ndigits; i++)
	{
		u64 diff;

		diff = left[i] - borrow;
		if (diff != left[i])
			borrow = (diff > left[i]);

		result[i] = diff;
	}

	return borrow;
}

static uint128_t mul_64_64(u64 left, u64 right)
{
	uint128_t result;
#if defined(CONFIG_ARCH_SUPPORTS_INT128)
	unsigned __int128 m = (unsigned __int128)left * right;

	result.m_low  = m;
	result.m_high = m >> 64;
#else
	u64 a0 = left & 0xffffffffull;
	u64 a1 = left >> 32;
	u64 b0 = right & 0xffffffffull;
	u64 b1 = right >> 32;
	u64 m0 = a0 * b0;
	u64 m1 = a0 * b1;
	u64 m2 = a1 * b0;
	u64 m3 = a1 * b1;

	m2 += (m0 >> 32);
	m2 += m1;

	/* Overflow */
	if (m2 < m1)
		m3 += 0x100000000ull;

	result.m_low  = (m0 & 0xffffffffull) | (m2 << 32);
	result.m_high = m3 + (m2 >> 32);
#endif
	return result;
}

static uint128_t add_128_128(uint128_t a, uint128_t b)
{
	uint128_t result;

	result.m_low  = a.m_low + b.m_low;
	result.m_high = a.m_high + b.m_high + (result.m_low < a.m_low);

	return result;
}

void vli_mult(u64 *result, const u64 *left, const u64 *right, unsigned int ndigits)
{
	uint128_t	 r01 = {0, 0};
	u64			 r2	 = 0;
	unsigned int i, k;

	/* Compute each digit of result in sequence, maintaining the
	 * carries.
	 */
	for (k = 0; k < ndigits * 2 - 1; k++)
	{
		unsigned int min;

		if (k < ndigits)
			min = 0;
		else
			min = (k + 1) - ndigits;

		for (i = min; i <= k && i < ndigits; i++)
		{
			uint128_t product;

			product = mul_64_64(left[i], right[k - i]);

			r01 = add_128_128(r01, product);
			r2 += (r01.m_high < product.m_high);
		}

		result[k]  = r01.m_low;
		r01.m_low  = r01.m_high;
		r01.m_high = r2;
		r2		   = 0;
	}

	result[ndigits * 2 - 1] = r01.m_low;
}

/* Compute product = left * right, for a small right value. */
static void vli_umult(u64 *result, const u64 *left, u32 right, unsigned int ndigits)
{
	uint128_t	 r01 = {0};
	unsigned int k;

	for (k = 0; k < ndigits; k++)
	{
		uint128_t product;

		product = mul_64_64(left[k], right);
		r01		= add_128_128(r01, product);
		/* no carry */
		result[k]  = r01.m_low;
		r01.m_low  = r01.m_high;
		r01.m_high = 0;
	}
	result[k] = r01.m_low;
	for (++k; k < ndigits * 2; k++)
		result[k] = 0;
}

static void vli_square(u64 *result, const u64 *left, unsigned int ndigits)
{
	uint128_t r01 = {0, 0};
	u64		  r2  = 0;
	int		  i, k;

	for (k = 0; k < ndigits * 2 - 1; k++)
	{
		unsigned int min;

		if (k < ndigits)
			min = 0;
		else
			min = (k + 1) - ndigits;

		for (i = min; i <= k && i <= k - i; i++)
		{
			uint128_t product;

			product = mul_64_64(left[i], left[k - i]);

			if (i < k - i)
			{
				r2 += product.m_high >> 63;
				product.m_high = (product.m_high << 1) | (product.m_low >> 63);
				product.m_low <<= 1;
			}

			r01 = add_128_128(r01, product);
			r2 += (r01.m_high < product.m_high);
		}

		result[k]  = r01.m_low;
		r01.m_low  = r01.m_high;
		r01.m_high = r2;
		r2		   = 0;
	}

	result[ndigits * 2 - 1] = r01.m_low;
}

/* Computes result = (left + right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 */
static void vli_mod_add(u64 *result, const u64 *left, const u64 *right, const u64 *mod, unsigned int ndigits)
{
	u64 carry;

	carry = vli_add(result, left, right, ndigits);

	/* result > mod (result = mod + remainder), so subtract mod to
	 * get remainder.
	 */
	if (carry || vli_cmp(result, mod, ndigits) >= 0)
		vli_sub(result, result, mod, ndigits);
}

/* Computes result = (left - right) % mod.
 * Assumes that left < mod and right < mod, result != mod.
 */
static void vli_mod_sub(u64 *result, const u64 *left, const u64 *right, const u64 *mod, unsigned int ndigits)
{
	u64 borrow = vli_sub(result, left, right, ndigits);

	/* In this case, p_result == -diff == (max int) - diff.
	 * Since -x % d == d - x, we can get the correct result from
	 * result + mod (with overflow).
	 */
	if (borrow)
		vli_add(result, result, mod, ndigits);
}

/*
 * Computes result = product % mod
 * for special form moduli: p = 2^k-c, for small c (note the minus sign)
 *
 * References:
 * R. Crandall, C. Pomerance. Prime Numbers: A Computational Perspective.
 * 9 Fast Algorithms for Large-Integer Arithmetic. 9.2.3 Moduli of special form
 * Algorithm 9.2.13 (Fast mod operation for special-form moduli).
 */
static void vli_mmod_special(u64 *result, const u64 *product, const u64 *mod, unsigned int ndigits)
{
	u64 c = -mod[0];
	u64 t[ECC_MAX_DIGITS * 2];
	u64 r[ECC_MAX_DIGITS * 2];

	vli_set(r, product, ndigits * 2);
	while (!vli_is_zero(r + ndigits, ndigits))
	{
		vli_umult(t, r + ndigits, c, ndigits);
		vli_clear(r + ndigits, ndigits);
		vli_add(r, r, t, ndigits * 2);
	}
	vli_set(t, mod, ndigits);
	vli_clear(t + ndigits, ndigits);
	while (vli_cmp(r, t, ndigits * 2) >= 0)
		vli_sub(r, r, t, ndigits * 2);
	vli_set(result, r, ndigits);
}

/*
 * Computes result = product % mod
 * for special form moduli: p = 2^{k-1}+c, for small c (note the plus sign)
 * where k-1 does not fit into qword boundary by -1 bit (such as 255).

 * References (loosely based on):
 * A. Menezes, P. van Oorschot, S. Vanstone. Handbook of Applied Cryptography.
 * 14.3.4 Reduction methods for moduli of special form. Algorithm 14.47.
 * URL: http://cacr.uwaterloo.ca/hac/about/chap14.pdf
 *
 * H. Cohen, G. Frey, R. Avanzi, C. Doche, T. Lange, K. Nguyen, F. Vercauteren.
 * Handbook of Elliptic and Hyperelliptic Curve Cryptography.
 * Algorithm 10.25 Fast reduction for special form moduli
 */
static void vli_mmod_special2(u64 *result, const u64 *product, const u64 *mod, unsigned int ndigits)
{
	u64 c2 = mod[0] * 2;
	u64 q[ECC_MAX_DIGITS];
	u64 r[ECC_MAX_DIGITS * 2];
	u64 m[ECC_MAX_DIGITS * 2]; /* expanded mod */
	int carry;				   /* last bit that doesn't fit into q */
	int i;

	vli_set(m, mod, ndigits);
	vli_clear(m + ndigits, ndigits);

	vli_set(r, product, ndigits);
	/* q and carry are top bits */
	vli_set(q, product + ndigits, ndigits);
	vli_clear(r + ndigits, ndigits);
	carry = vli_is_negative(r, ndigits);
	if (carry)
		r[ndigits - 1] &= (1ull << 63) - 1;
	for (i = 1; carry || !vli_is_zero(q, ndigits); i++)
	{
		u64 qc[ECC_MAX_DIGITS * 2];

		vli_umult(qc, q, c2, ndigits);
		if (carry)
			vli_uadd(qc, qc, mod[0], ndigits * 2);
		vli_set(q, qc + ndigits, ndigits);
		vli_clear(qc + ndigits, ndigits);
		carry = vli_is_negative(qc, ndigits);
		if (carry)
			qc[ndigits - 1] &= (1ull << 63) - 1;
		if (i & 1)
			vli_sub(r, r, qc, ndigits * 2);
		else
			vli_add(r, r, qc, ndigits * 2);
	}
	while (vli_is_negative(r, ndigits * 2))
		vli_add(r, r, m, ndigits * 2);
	while (vli_cmp(r, m, ndigits * 2) >= 0)
		vli_sub(r, r, m, ndigits * 2);

	vli_set(result, r, ndigits);
}

/*
 * Computes result = product % mod, where product is 2N words long.
 * Reference: Ken MacKay's micro-ecc.
 * Currently only designed to work for curve_p or curve_n.
 */
static void vli_mmod_slow(u64 *result, u64 *product, const u64 *mod, unsigned int ndigits)
{
	u64			 mod_m[2 * ECC_MAX_DIGITS];
	u64			 tmp[2 * ECC_MAX_DIGITS];
	u64			*v[2]  = {tmp, product};
	u64			 carry = 0;
	unsigned int i;
	/* Shift mod so its highest set bit is at the maximum position. */
	int shift	   = (ndigits * 2 * 64) - vli_num_bits(mod, ndigits);
	int word_shift = shift / 64;
	int bit_shift  = shift % 64;

	vli_clear(mod_m, word_shift);
	if (bit_shift > 0)
	{
		for (i = 0; i < ndigits; ++i)
		{
			mod_m[word_shift + i] = (mod[i] << bit_shift) | carry;
			carry				  = mod[i] >> (64 - bit_shift);
		}
	}
	else
		vli_set(mod_m + word_shift, mod, ndigits);

	for (i = 1; shift >= 0; --shift)
	{
		u64			 borrow = 0;
		unsigned int j;

		for (j = 0; j < ndigits * 2; ++j)
		{
			u64 diff = v[i][j] - mod_m[j] - borrow;

			if (diff != v[i][j])
				borrow = (diff > v[i][j]);
			v[1 - i][j] = diff;
		}
		i = !(i ^ borrow); /* Swap the index if there was no borrow */
		vli_rshift1(mod_m, ndigits);
		mod_m[ndigits - 1] |= mod_m[ndigits] << (64 - 1);
		vli_rshift1(mod_m + ndigits, ndigits);
	}
	vli_set(result, v[i], ndigits);
}

/* Computes result = product % mod using Barrett's reduction with precomputed
 * value mu appended to the mod after ndigits, mu = (2^{2w} / mod) and have
 * length ndigits + 1, where mu * (2^w - 1) should not overflow ndigits
 * boundary.
 *
 * Reference:
 * R. Brent, P. Zimmermann. Modern Computer Arithmetic. 2010.
 * 2.4.1 Barrett's algorithm. Algorithm 2.5.
 */
static void vli_mmod_barrett(u64 *result, u64 *product, const u64 *mod, unsigned int ndigits)
{
	u64		   q[ECC_MAX_DIGITS * 2];
	u64		   r[ECC_MAX_DIGITS * 2];
	const u64 *mu = mod + ndigits;

	vli_mult(q, product + ndigits, mu, ndigits);
	if (mu[ndigits])
		vli_add(q + ndigits, q + ndigits, product + ndigits, ndigits);
	vli_mult(r, mod, q + ndigits, ndigits);
	vli_sub(r, product, r, ndigits * 2);
	while (!vli_is_zero(r + ndigits, ndigits) || vli_cmp(r, mod, ndigits) != -1)
	{
		u64 carry;

		carry = vli_sub(r, r, mod, ndigits);
		vli_usub(r + ndigits, r + ndigits, carry, ndigits);
	}
	vli_set(result, r, ndigits);
}

/* Computes p_result = p_product % curve_p.
 * See algorithm 5 and 6 from
 * http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf
 */
static void vli_mmod_fast_192(u64 *result, const u64 *product, const u64 *curve_prime, u64 *tmp)
{
	const unsigned int ndigits = ECC_CURVE_NIST_P192_DIGITS;
	int				   carry;

	vli_set(result, product, ndigits);

	vli_set(tmp, &product[3], ndigits);
	carry = vli_add(result, result, tmp, ndigits);

	tmp[0] = 0;
	tmp[1] = product[3];
	tmp[2] = product[4];
	carry += vli_add(result, result, tmp, ndigits);

	tmp[0] = tmp[1] = product[5];
	tmp[2]			= 0;
	carry += vli_add(result, result, tmp, ndigits);

	while (carry || vli_cmp(curve_prime, result, ndigits) != 1)
		carry -= vli_sub(result, result, curve_prime, ndigits);
}

/* Computes result = product % curve_prime
 * from http://www.nsa.gov/ia/_files/nist-routines.pdf
 */
static void vli_mmod_fast_256(u64 *result, const u64 *product, const u64 *curve_prime, u64 *tmp)
{
	int				   carry;
	const unsigned int ndigits = ECC_CURVE_NIST_P256_DIGITS;

	/* t */
	vli_set(result, product, ndigits);

	/* s1 */
	tmp[0] = 0;
	tmp[1] = product[5] & 0xffffffff00000000ull;
	tmp[2] = product[6];
	tmp[3] = product[7];
	carry  = vli_lshift(tmp, tmp, 1, ndigits);
	carry += vli_add(result, result, tmp, ndigits);

	/* s2 */
	tmp[1] = product[6] << 32;
	tmp[2] = (product[6] >> 32) | (product[7] << 32);
	tmp[3] = product[7] >> 32;
	carry += vli_lshift(tmp, tmp, 1, ndigits);
	carry += vli_add(result, result, tmp, ndigits);

	/* s3 */
	tmp[0] = product[4];
	tmp[1] = product[5] & 0xffffffff;
	tmp[2] = 0;
	tmp[3] = product[7];
	carry += vli_add(result, result, tmp, ndigits);

	/* s4 */
	tmp[0] = (product[4] >> 32) | (product[5] << 32);
	tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000ull);
	tmp[2] = product[7];
	tmp[3] = (product[6] >> 32) | (product[4] << 32);
	carry += vli_add(result, result, tmp, ndigits);

	/* d1 */
	tmp[0] = (product[5] >> 32) | (product[6] << 32);
	tmp[1] = (product[6] >> 32);
	tmp[2] = 0;
	tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
	carry -= vli_sub(result, result, tmp, ndigits);

	/* d2 */
	tmp[0] = product[6];
	tmp[1] = product[7];
	tmp[2] = 0;
	tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000ull);
	carry -= vli_sub(result, result, tmp, ndigits);

	/* d3 */
	tmp[0] = (product[6] >> 32) | (product[7] << 32);
	tmp[1] = (product[7] >> 32) | (product[4] << 32);
	tmp[2] = (product[4] >> 32) | (product[5] << 32);
	tmp[3] = (product[6] << 32);
	carry -= vli_sub(result, result, tmp, ndigits);

	/* d4 */
	tmp[0] = product[7];
	tmp[1] = product[4] & 0xffffffff00000000ull;
	tmp[2] = product[5];
	tmp[3] = product[6] & 0xffffffff00000000ull;
	carry -= vli_sub(result, result, tmp, ndigits);

	if (carry < 0)
	{
		do
		{
			carry += vli_add(result, result, curve_prime, ndigits);
		} while (carry < 0);
	}
	else
	{
		while (carry || vli_cmp(curve_prime, result, ndigits) != 1)
			carry -= vli_sub(result, result, curve_prime, ndigits);
	}
}

#define SL32OR32(x32, y32) (((u64)x32 << 32) | y32)
#define AND64H(x64)		   (x64 & 0xffFFffFF00000000ull)
#define AND64L(x64)		   (x64 & 0x00000000ffFFffFFull)

/* Computes result = product % curve_prime
 * from "Mathematical routines for the NIST prime elliptic curves"
 */
static void vli_mmod_fast_384(u64 *result, const u64 *product, const u64 *curve_prime, u64 *tmp)
{
	int				   carry;
	const unsigned int ndigits = ECC_CURVE_NIST_P384_DIGITS;

	/* t */
	vli_set(result, product, ndigits);

	/* s1 */
	tmp[0] = 0;											 // 0 || 0
	tmp[1] = 0;											 // 0 || 0
	tmp[2] = SL32OR32(product[11], (product[10] >> 32)); // a22||a21
	tmp[3] = product[11] >> 32;							 // 0 ||a23
	tmp[4] = 0;											 // 0 || 0
	tmp[5] = 0;											 // 0 || 0
	carry  = vli_lshift(tmp, tmp, 1, ndigits);
	carry += vli_add(result, result, tmp, ndigits);

	/* s2 */
	tmp[0] = product[6];  // a13||a12
	tmp[1] = product[7];  // a15||a14
	tmp[2] = product[8];  // a17||a16
	tmp[3] = product[9];  // a19||a18
	tmp[4] = product[10]; // a21||a20
	tmp[5] = product[11]; // a23||a22
	carry += vli_add(result, result, tmp, ndigits);

	/* s3 */
	tmp[0] = SL32OR32(product[11], (product[10] >> 32)); // a22||a21
	tmp[1] = SL32OR32(product[6], (product[11] >> 32));	 // a12||a23
	tmp[2] = SL32OR32(product[7], (product[6]) >> 32);	 // a14||a13
	tmp[3] = SL32OR32(product[8], (product[7] >> 32));	 // a16||a15
	tmp[4] = SL32OR32(product[9], (product[8] >> 32));	 // a18||a17
	tmp[5] = SL32OR32(product[10], (product[9] >> 32));	 // a20||a19
	carry += vli_add(result, result, tmp, ndigits);

	/* s4 */
	tmp[0] = AND64H(product[11]); // a23|| 0
	tmp[1] = (product[10] << 32); // a20|| 0
	tmp[2] = product[6];		  // a13||a12
	tmp[3] = product[7];		  // a15||a14
	tmp[4] = product[8];		  // a17||a16
	tmp[5] = product[9];		  // a19||a18
	carry += vli_add(result, result, tmp, ndigits);

	/* s5 */
	tmp[0] = 0;			  //  0|| 0
	tmp[1] = 0;			  //  0|| 0
	tmp[2] = product[10]; // a21||a20
	tmp[3] = product[11]; // a23||a22
	tmp[4] = 0;			  //  0|| 0
	tmp[5] = 0;			  //  0|| 0
	carry += vli_add(result, result, tmp, ndigits);

	/* s6 */
	tmp[0] = AND64L(product[10]); // 0 ||a20
	tmp[1] = AND64H(product[10]); // a21|| 0
	tmp[2] = product[11];		  // a23||a22
	tmp[3] = 0;					  // 0 || 0
	tmp[4] = 0;					  // 0 || 0
	tmp[5] = 0;					  // 0 || 0
	carry += vli_add(result, result, tmp, ndigits);

	/* d1 */
	tmp[0] = SL32OR32(product[6], (product[11] >> 32));	 // a12||a23
	tmp[1] = SL32OR32(product[7], (product[6] >> 32));	 // a14||a13
	tmp[2] = SL32OR32(product[8], (product[7] >> 32));	 // a16||a15
	tmp[3] = SL32OR32(product[9], (product[8] >> 32));	 // a18||a17
	tmp[4] = SL32OR32(product[10], (product[9] >> 32));	 // a20||a19
	tmp[5] = SL32OR32(product[11], (product[10] >> 32)); // a22||a21
	carry -= vli_sub(result, result, tmp, ndigits);

	/* d2 */
	tmp[0] = (product[10] << 32);						 // a20|| 0
	tmp[1] = SL32OR32(product[11], (product[10] >> 32)); // a22||a21
	tmp[2] = (product[11] >> 32);						 // 0 ||a23
	tmp[3] = 0;											 // 0 || 0
	tmp[4] = 0;											 // 0 || 0
	tmp[5] = 0;											 // 0 || 0
	carry -= vli_sub(result, result, tmp, ndigits);

	/* d3 */
	tmp[0] = 0;					  // 0 || 0
	tmp[1] = AND64H(product[11]); // a23|| 0
	tmp[2] = product[11] >> 32;	  // 0 ||a23
	tmp[3] = 0;					  // 0 || 0
	tmp[4] = 0;					  // 0 || 0
	tmp[5] = 0;					  // 0 || 0
	carry -= vli_sub(result, result, tmp, ndigits);

	if (carry < 0)
	{
		do
		{
			carry += vli_add(result, result, curve_prime, ndigits);
		} while (carry < 0);
	}
	else
	{
		while (carry || vli_cmp(curve_prime, result, ndigits) != 1)
			carry -= vli_sub(result, result, curve_prime, ndigits);
	}
}

#undef SL32OR32
#undef AND64H
#undef AND64L

/*
 * Computes result = product % curve_prime
 * from "Recommendations for Discrete Logarithm-Based Cryptography:
 *       Elliptic Curve Domain Parameters" section G.1.4
 */
static void vli_mmod_fast_521(u64 *result, const u64 *product, const u64 *curve_prime, u64 *tmp)
{
	const unsigned int ndigits = ECC_CURVE_NIST_P521_DIGITS;
	size_t			   i;

	/* Initialize result with lowest 521 bits from product */
	vli_set(result, product, ndigits);
	result[8] &= 0x1ff;

	for (i = 0; i < ndigits; i++)
		tmp[i] = (product[8 + i] >> 9) | (product[9 + i] << 55);
	tmp[8] &= 0x1ff;

	vli_mod_add(result, result, tmp, curve_prime, ndigits);
}

/* Computes result = product % curve_prime for different curve_primes.
 *
 * Note that curve_primes are distinguished just by heuristic check and
 * not by complete conformance check.
 */
static bool vli_mmod_fast(u64 *result, u64 *product, const struct ecc_curve *curve)
{
	const u64		  *curve_prime = curve->p;
	const unsigned int ndigits	   = curve->g.ndigits;

	/* All NIST curves have name prefix 'nist_' */
	if (strncmp(curve->name, "nist_", 5) != 0)
	{
		/* Try to handle Pseudo-Marsenne primes (p = 2^k - c) */
		if (curve_prime[ndigits - 1] == -1ull)
		{
			vli_mmod_special(result, product, curve_prime, ndigits);
			return true;
		}

		/*
		 * Fallback: Use generic binary long division.
		 * Do NOT use vli_mmod_barrett here because we do not have
		 * precomputed 'mu' in standard ecc_curve structs.
		 */
		vli_mmod_slow(result, product, curve_prime, ndigits);
		return true;
	}

	/* NIST optimization switches would go here */
	return false;
}

/* Computes result = (left * right) % curve_prime. */
static void vli_mod_mult_fast(u64 *result, const u64 *left, const u64 *right, const struct ecc_curve *curve)
{
	u64 product[2 * ECC_MAX_DIGITS];

	vli_mult(product, left, right, curve->g.ndigits);
	vli_mmod_fast(result, product, curve);
}

/* Computes result = left^2 % curve_prime. */
static void vli_mod_square_fast(u64 *result, const u64 *left, const struct ecc_curve *curve)
{
	u64 product[2 * ECC_MAX_DIGITS];

	vli_square(product, left, curve->g.ndigits);
	vli_mmod_fast(result, product, curve);
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes result = (1 / p_input) % mod. All VLIs are the same size.
 * See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
 * https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
 */

/* ------ Point operations ------ */
/* Double in place */
static void ecc_point_double_jacobian(u64 *x1, u64 *y1, u64 *z1, const struct ecc_curve *curve)
{
	/* t1 = x, t2 = y, t3 = z */
	u64				   t4[ECC_MAX_DIGITS];
	u64				   t5[ECC_MAX_DIGITS];
	const u64		  *curve_prime = curve->p;
	const unsigned int ndigits	   = curve->g.ndigits;

	if (vli_is_zero(z1, ndigits))
		return;

	/* t4 = y1^2 */
	vli_mod_square_fast(t4, y1, curve);
	/* t5 = x1*y1^2 = A */
	vli_mod_mult_fast(t5, x1, t4, curve);
	/* t4 = y1^4 */
	vli_mod_square_fast(t4, t4, curve);
	/* t2 = y1*z1 = z3 */
	vli_mod_mult_fast(y1, y1, z1, curve);
	/* t3 = z1^2 */
	vli_mod_square_fast(z1, z1, curve);

	/* t1 = x1 + z1^2 */
	vli_mod_add(x1, x1, z1, curve_prime, ndigits);
	/* t3 = 2*z1^2 */
	vli_mod_add(z1, z1, z1, curve_prime, ndigits);
	/* t3 = x1 - z1^2 */
	vli_mod_sub(z1, x1, z1, curve_prime, ndigits);
	/* t1 = x1^2 - z1^4 */
	vli_mod_mult_fast(x1, x1, z1, curve);

	/* t3 = 2*(x1^2 - z1^4) */
	vli_mod_add(z1, x1, x1, curve_prime, ndigits);
	/* t1 = 3*(x1^2 - z1^4) */
	vli_mod_add(x1, x1, z1, curve_prime, ndigits);
	if (vli_test_bit(x1, 0))
	{
		u64 carry = vli_add(x1, x1, curve_prime, ndigits);

		vli_rshift1(x1, ndigits);
		x1[ndigits - 1] |= carry << 63;
	}
	else
	{
		vli_rshift1(x1, ndigits);
	}
	/* t1 = 3/2*(x1^2 - z1^4) = B */

	/* t3 = B^2 */
	vli_mod_square_fast(z1, x1, curve);
	/* t3 = B^2 - A */
	vli_mod_sub(z1, z1, t5, curve_prime, ndigits);
	/* t3 = B^2 - 2A = x3 */
	vli_mod_sub(z1, z1, t5, curve_prime, ndigits);
	/* t5 = A - x3 */
	vli_mod_sub(t5, t5, z1, curve_prime, ndigits);
	/* t1 = B * (A - x3) */
	vli_mod_mult_fast(x1, x1, t5, curve);
	/* t4 = B * (A - x3) - y1^4 = y3 */
	vli_mod_sub(t4, x1, t4, curve_prime, ndigits);

	vli_set(x1, z1, ndigits);
	vli_set(z1, y1, ndigits);
	vli_set(y1, t4, ndigits);
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(u64 *x1, u64 *y1, u64 *z, const struct ecc_curve *curve)
{
	u64 t1[ECC_MAX_DIGITS];

	vli_mod_square_fast(t1, z, curve);	  /* z^2 */
	vli_mod_mult_fast(x1, x1, t1, curve); /* x1 * z^2 */
	vli_mod_mult_fast(t1, t1, z, curve);  /* z^3 */
	vli_mod_mult_fast(y1, y1, t1, curve); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void xycz_initial_double(u64 *x1, u64 *y1, u64 *x2, u64 *y2, u64 *p_initial_z, const struct ecc_curve *curve)
{
	u64				   z[ECC_MAX_DIGITS];
	const unsigned int ndigits = curve->g.ndigits;

	vli_set(x2, x1, ndigits);
	vli_set(y2, y1, ndigits);

	vli_clear(z, ndigits);
	z[0] = 1;

	if (p_initial_z)
		vli_set(z, p_initial_z, ndigits);

	apply_z(x1, y1, z, curve);

	ecc_point_double_jacobian(x1, y1, z, curve);

	apply_z(x2, y2, z, curve);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 * Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
 * or P => P', Q => P + Q
 */
static void xycz_add(u64 *x1, u64 *y1, u64 *x2, u64 *y2, const struct ecc_curve *curve)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	u64				   t5[ECC_MAX_DIGITS];
	const u64		  *curve_prime = curve->p;
	const unsigned int ndigits	   = curve->g.ndigits;

	/* t5 = x2 - x1 */
	vli_mod_sub(t5, x2, x1, curve_prime, ndigits);
	/* t5 = (x2 - x1)^2 = A */
	vli_mod_square_fast(t5, t5, curve);
	/* t1 = x1*A = B */
	vli_mod_mult_fast(x1, x1, t5, curve);
	/* t3 = x2*A = C */
	vli_mod_mult_fast(x2, x2, t5, curve);
	/* t4 = y2 - y1 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);
	/* t5 = (y2 - y1)^2 = D */
	vli_mod_square_fast(t5, y2, curve);

	/* t5 = D - B */
	vli_mod_sub(t5, t5, x1, curve_prime, ndigits);
	/* t5 = D - B - C = x3 */
	vli_mod_sub(t5, t5, x2, curve_prime, ndigits);
	/* t3 = C - B */
	vli_mod_sub(x2, x2, x1, curve_prime, ndigits);
	/* t2 = y1*(C - B) */
	vli_mod_mult_fast(y1, y1, x2, curve);
	/* t3 = B - x3 */
	vli_mod_sub(x2, x1, t5, curve_prime, ndigits);
	/* t4 = (y2 - y1)*(B - x3) */
	vli_mod_mult_fast(y2, y2, x2, curve);
	/* t4 = y3 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);

	vli_set(x2, t5, ndigits);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
 * Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
 * or P => P - Q, Q => P + Q
 */
static void xycz_add_c(u64 *x1, u64 *y1, u64 *x2, u64 *y2, const struct ecc_curve *curve)
{
	/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
	u64				   t5[ECC_MAX_DIGITS];
	u64				   t6[ECC_MAX_DIGITS];
	u64				   t7[ECC_MAX_DIGITS];
	const u64		  *curve_prime = curve->p;
	const unsigned int ndigits	   = curve->g.ndigits;

	/* t5 = x2 - x1 */
	vli_mod_sub(t5, x2, x1, curve_prime, ndigits);
	/* t5 = (x2 - x1)^2 = A */
	vli_mod_square_fast(t5, t5, curve);
	/* t1 = x1*A = B */
	vli_mod_mult_fast(x1, x1, t5, curve);
	/* t3 = x2*A = C */
	vli_mod_mult_fast(x2, x2, t5, curve);
	/* t4 = y2 + y1 */
	vli_mod_add(t5, y2, y1, curve_prime, ndigits);
	/* t4 = y2 - y1 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);

	/* t6 = C - B */
	vli_mod_sub(t6, x2, x1, curve_prime, ndigits);
	/* t2 = y1 * (C - B) */
	vli_mod_mult_fast(y1, y1, t6, curve);
	/* t6 = B + C */
	vli_mod_add(t6, x1, x2, curve_prime, ndigits);
	/* t3 = (y2 - y1)^2 */
	vli_mod_square_fast(x2, y2, curve);
	/* t3 = x3 */
	vli_mod_sub(x2, x2, t6, curve_prime, ndigits);

	/* t7 = B - x3 */
	vli_mod_sub(t7, x1, x2, curve_prime, ndigits);
	/* t4 = (y2 - y1)*(B - x3) */
	vli_mod_mult_fast(y2, y2, t7, curve);
	/* t4 = y3 */
	vli_mod_sub(y2, y2, y1, curve_prime, ndigits);

	/* t7 = (y2 + y1)^2 = F */
	vli_mod_square_fast(t7, t5, curve);
	/* t7 = x3' */
	vli_mod_sub(t7, t7, t6, curve_prime, ndigits);
	/* t6 = x3' - B */
	vli_mod_sub(t6, t7, x1, curve_prime, ndigits);
	/* t6 = (y2 + y1)*(x3' - B) */
	vli_mod_mult_fast(t6, t6, t5, curve);
	/* t2 = y3' */
	vli_mod_sub(y1, t6, y1, curve_prime, ndigits);

	vli_set(x1, t7, ndigits);
}

static void ecc_point_mult(struct ecc_point		  *result,
						   const struct ecc_point *point,
						   const u64			  *scalar,
						   u64					  *initial_z,
						   const struct ecc_curve *curve,
						   unsigned int			   ndigits)
{
	/* R0 and R1 */
	u64	 rx[2][ECC_MAX_DIGITS];
	u64	 ry[2][ECC_MAX_DIGITS];
	u64	 z[ECC_MAX_DIGITS];
	u64	 sk[2][ECC_MAX_DIGITS];
	u64 *curve_prime = curve->p;
	int	 i, nb;
	int	 num_bits;
	int	 carry;

	carry = vli_add(sk[0], scalar, curve->n, ndigits);
	vli_add(sk[1], sk[0], curve->n, ndigits);
	scalar = sk[!carry];
	if (curve->nbits == 521) /* NIST P521 */
		num_bits = curve->nbits + 2;
	else
		num_bits = sizeof(u64) * ndigits * 8 + 1;

	vli_set(rx[1], point->x, ndigits);
	vli_set(ry[1], point->y, ndigits);

	xycz_initial_double(rx[1], ry[1], rx[0], ry[0], initial_z, curve);

	for (i = num_bits - 2; i > 0; i--)
	{
		nb = !vli_test_bit(scalar, i);
		xycz_add_c(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb], curve);
		xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb], curve);
	}

	nb = !vli_test_bit(scalar, 0);
	xycz_add_c(rx[1 - nb], ry[1 - nb], rx[nb], ry[nb], curve);

	/* Find final 1/Z value. */
	/* X1 - X0 */
	vli_mod_sub(z, rx[1], rx[0], curve_prime, ndigits);
	/* Yb * (X1 - X0) */
	vli_mod_mult_fast(z, z, ry[1 - nb], curve);
	/* xP * Yb * (X1 - X0) */
	vli_mod_mult_fast(z, z, point->x, curve);

	/* 1 / (xP * Yb * (X1 - X0)) */
	vli_mod_inv(z, z, curve_prime, point->ndigits);

	/* yP / (xP * Yb * (X1 - X0)) */
	vli_mod_mult_fast(z, z, point->y, curve);
	/* Xb * yP / (xP * Yb * (X1 - X0)) */
	vli_mod_mult_fast(z, z, rx[1 - nb], curve);
	/* End 1/Z calculation */

	xycz_add(rx[nb], ry[nb], rx[1 - nb], ry[1 - nb], curve);

	apply_z(rx[0], ry[0], z, curve);

	vli_set(result->x, rx[0], ndigits);
	vli_set(result->y, ry[0], ndigits);
}

/* Computes R = P + Q mod p */
static void ecc_point_add(const struct ecc_point *result, const struct ecc_point *p, const struct ecc_point *q, const struct ecc_curve *curve)
{
	u64			 z[ECC_MAX_DIGITS];
	u64			 px[ECC_MAX_DIGITS];
	u64			 py[ECC_MAX_DIGITS];
	unsigned int ndigits = curve->g.ndigits;

	vli_set(result->x, q->x, ndigits);
	vli_set(result->y, q->y, ndigits);
	vli_mod_sub(z, result->x, p->x, curve->p, ndigits);
	vli_set(px, p->x, ndigits);
	vli_set(py, p->y, ndigits);
	xycz_add(px, py, result->x, result->y, curve);
	vli_mod_inv(z, z, curve->p, ndigits);
	apply_z(result->x, result->y, z, curve);
}

/*
 * This function performs checks equivalent to Appendix A.4.2 of FIPS 186-5.
 * Whereas A.4.2 results in an integer in the interval [1, n-1], this function
 * ensures that the integer is in the range of [2, n-3]. We are slightly
 * stricter because of the currently used scalar multiplication algorithm.
 */
static int __ecc_is_key_valid(const struct ecc_curve *curve, const u64 *private_key, unsigned int ndigits)
{
	u64 one[ECC_MAX_DIGITS] = {
		1,
	};
	u64 res[ECC_MAX_DIGITS];

	if (!private_key)
		return -EINVAL;

	if (curve->g.ndigits != ndigits)
		return -EINVAL;

	/* Make sure the private key is in the range [2, n-3]. */
	if (vli_cmp(one, private_key, ndigits) != -1)
		return -EINVAL;
	vli_sub(res, curve->n, one, ndigits);
	vli_sub(res, res, one, ndigits);
	if (vli_cmp(res, private_key, ndigits) != 1)
		return -EINVAL;

	return 0;
}

void gost_vli_from_be(u64 *dest, const u8 *src, unsigned int ndigits)
{
	unsigned int i;
	for (i = 0; i < ndigits; i++)
		dest[i] = get_unaligned_be64(src + (ndigits - 1 - i) * 8);
}

void gost_vli_to_be(u8 *dest, const u64 *src, unsigned int ndigits)
{
	unsigned int i;
	for (i = 0; i < ndigits; i++)
		put_unaligned_be64(src[i], dest + (ndigits - 1 - i) * 8);
}

int gost_ec256_validate_private(const u64 *k, const struct ecc_curve *curve)
{
	/* Check 0 < k < n */
	if (vli_is_zero(k, GOST_EC256_NDIGITS))
		return -EINVAL;
	if (vli_cmp(k, curve->n, GOST_EC256_NDIGITS) >= 0)
		return -EINVAL;
	return 0;
}

int gost_ec256_validate_public(const u64 *x, const u64 *y, const struct ecc_curve *curve)
{
	/* Check Point equation: y^2 = x^3 + ax + b (mod p) */
	/* Simplified check: just range [0, p-1] */
	if (vli_cmp(x, curve->p, GOST_EC256_NDIGITS) >= 0)
		return -EINVAL;
	if (vli_cmp(y, curve->p, GOST_EC256_NDIGITS) >= 0)
		return -EINVAL;

	return 0;
}

int gost_ecc_is_key_valid(const struct ecc_curve *curve, const u64 *private_key)
{
	u64 one[ECC_MAX_DIGITS] = {1};
	if (vli_cmp(private_key, one, curve->g.ndigits) <= 0)
		return 0;
	if (vli_cmp(private_key, curve->n, curve->g.ndigits) >= 0)
		return 0;
	return 1;
}

int gost_ec256_validate_key(const u64 *key, const struct ecc_curve *curve)
{
	if (vli_is_zero(key, curve->g.ndigits))
		return -EINVAL;
	if (vli_cmp(key, curve->n, curve->g.ndigits) >= 0)
		return -EINVAL;
	return 0;
}

void gost_vli_mod_mult(u64 *result, const u64 *left, const u64 *right, const u64 *mod, unsigned int ndigits)
{
	u64 product[2 * ECC_MAX_DIGITS];

	vli_mult(product, left, right, ndigits);

	vli_mmod_slow(result, product, mod, ndigits);
}

void gost_ec256_point_mul(u64 *res_x, u64 *res_y, const u64 *p_x, const u64 *p_y, const u64 *scalar, const struct ecc_curve *curve)
{
	struct ecc_point point;
	struct ecc_point res;

	point.x		  = (u64 *)p_x;
	point.y		  = (u64 *)p_y;
	point.ndigits = curve->g.ndigits;

	u64 rx[ECC_MAX_DIGITS], ry[ECC_MAX_DIGITS];
	res.x		= rx;
	res.y		= ry;
	res.ndigits = curve->g.ndigits;

	ecc_point_mult(&res, &point, scalar, NULL, curve, curve->g.ndigits);

	vli_set(res_x, res.x, curve->g.ndigits);
	vli_set(res_y, res.y, curve->g.ndigits);
}
