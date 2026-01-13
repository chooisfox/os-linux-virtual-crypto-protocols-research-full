/*
 * GOST 34.10-2012 (VKO) Helper Functions
 */
#include "gost_math.h"

#include <crypto/kpp.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/uaccess.h>

/*
 * Internal struct definition to parse the buffer sent by the wrapper.
 * Must match the layout in gost_ec256.c (set_secret_helper).
 */
struct gost_vko_packed_fmt
{
	struct kpp_secret base;
	unsigned int	  key_len;
	u8				  key[GOST_EC256_KEY_SIZE];
	unsigned int	  ukm_len;
	u8				  ukm[];
} __packed;

int gost_vko_decode_key(const char *buf, unsigned int len, struct gost_vko_params *params)
{
	const struct gost_vko_packed_fmt *packed = (const void *)buf;
	unsigned int					  ukm_offset;

	if (len < sizeof(struct kpp_secret) + sizeof(unsigned int) + GOST_EC256_KEY_SIZE + sizeof(unsigned int))
		return -EINVAL;

	if (packed->key_len != GOST_EC256_KEY_SIZE)
		return -EINVAL;

	gost_vli_from_be(params->key, packed->key, GOST_EC256_NDIGITS);
	params->key_size = packed->key_len;

	ukm_offset = sizeof(struct kpp_secret) + sizeof(unsigned int) + GOST_EC256_KEY_SIZE;

	if (packed->ukm_len > 0)
	{
		unsigned int ukm_len = packed->ukm_len;

		if (len < ukm_offset + sizeof(unsigned int) + ukm_len)
			return -EINVAL;

		if (ukm_len > GOST_EC256_KEY_SIZE)
			return -EINVAL;

		params->ukm_size = ukm_len;

		u8 ukm_tmp[GOST_EC256_KEY_SIZE];
		memset(ukm_tmp, 0, sizeof(ukm_tmp));

		/* Right align: [00...00][UKM bytes] */
		memcpy(ukm_tmp + (GOST_EC256_KEY_SIZE - ukm_len), packed->ukm, ukm_len);

		gost_vli_from_be(params->ukm, ukm_tmp, GOST_EC256_NDIGITS);
	}
	else
	{
		params->ukm_size = 0;
		memset(params->ukm, 0, sizeof(params->ukm));
	}

	return 0;
}
