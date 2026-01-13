// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */

#include "device.h"
#include "gost/gost_ec256.h"
#include "gost/gost_kuznyechik.h"
#include "gost/gost_streebog.h"
#include "include/uapi/linux/wireguard.h"
#include "netlink.h"
#include "noise.h"
#include "queueing.h"
#include "ratelimiter.h"
#include "selftest/selftest.c"
#include "version.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/unaligned.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>

static int __init wg_mod_init(void)
{
	int ret;

	ret = gost_streebog_init_module();
	if (ret < 0)
		return ret;

	ret = gost_kuznyechik_init_tfms();
	if (ret < 0)
		goto err_kuznyechik;

	ret = gost_ec256_init_module();
	if (ret < 0)
		goto err_ec256;

#ifdef DEBUG
	RUN_TEST("Streebog-256", self_test_streebog);
	RUN_TEST("HMAC-Streebog-256", self_test_hmac_streebog);
	RUN_TEST("Kuznyechik-MGM", self_test_kuznyechik_mgm);
	RUN_TEST("GOST R 34.10-2012 (EC512)", self_test_gost_vko_generated);

	pr_info("WireGost crypto self-tests completed successfully.\n");
#endif
	ret = wg_allowedips_slab_init();
	if (ret < 0)
		goto err_allowedips;

	wg_noise_init();

	ret = wg_peer_init();
	if (ret < 0)
		goto err_peer;

	ret = wg_device_init();
	if (ret < 0)
		goto err_device;

	ret = wg_genetlink_init();
	if (ret < 0)
		goto err_netlink;

	pr_info("WireGost " WIREGOST_VERSION " loaded.\n");
	return 0;

err_netlink:
	wg_device_uninit();
err_device:
	wg_peer_uninit();
err_peer:
	wg_allowedips_slab_uninit();
err_allowedips:
err_tests:
	gost_ec256_cleanup_module();
err_ec256:
	gost_kuznyechik_uninit_tfms();
err_kuznyechik:
	gost_streebog_cleanup_module();
	return ret;
}

static void __exit wg_mod_exit(void)
{
	wg_genetlink_uninit();
	wg_device_uninit();
	wg_peer_uninit();
	wg_allowedips_slab_uninit();
	gost_ec256_cleanup_module();
	gost_kuznyechik_uninit_tfms();
	gost_streebog_cleanup_module();
}

module_init(wg_mod_init);
module_exit(wg_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("WireGost secure network tunnel");
MODULE_AUTHOR("Chudnikov A. A. <admin@redline-software.xyz>");
MODULE_VERSION(WIREGOST_VERSION);
MODULE_ALIAS_RTNL_LINK("wiregost");
MODULE_ALIAS_GENL_FAMILY("wiregost");
MODULE_IMPORT_NS("CRYPTO_INTERNAL");
