#ifndef _GOST_MATH_H
#define _GOST_MATH_H

#include <linux/kernel.h>
#include <linux/math.h>
#include <linux/types.h>

#include <crypto/internal/ecc.h>
#include <crypto/kpp.h>

/* Curve IDs */
#define GOST_CURVE_256A 101

#define GOST_EC256_NDIGITS 8
#define GOST_EC256_KEY_SIZE 64	  /* 64 bytes (512 bits) - Private Key */
#define GOST_EC256_POINT_SIZE 128 /* 128 bytes (X + Y)   - Public Key */

struct gost_vko_params {
	u64 key[GOST_EC256_NDIGITS];
	unsigned int key_size;
	u64 ukm[GOST_EC256_NDIGITS];
	unsigned int ukm_size;
};

u64 vli_add(u64 *result, const u64 *left, const u64 *right, unsigned int ndigits);
void vli_mult(u64 *result, const u64 *left, const u64 *right, unsigned int ndigits);
void gost_vli_from_be(u64 *dest, const u8 *src, unsigned int ndigits);
void gost_vli_to_be(u8 *dest, const u64 *src, unsigned int ndigits);

int gost_ec256_validate_key(const u64 *key, const struct ecc_curve *curve);
void gost_ec256_point_mul(u64 *res_x, u64 *res_y, const u64 *p_x, const u64 *p_y, const u64 *scalar, const struct ecc_curve *curve);
void gost_vli_mod_mult(u64 *result, const u64 *left, const u64 *right, const u64 *mod, unsigned int ndigits);

int gost_vko_decode_key(const char *buf, unsigned int len, struct gost_vko_params *params);

#endif /* _GOST_MATH_H */
