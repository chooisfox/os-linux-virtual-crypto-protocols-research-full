// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */

#include "cookie.h"

#include "device.h"
#include "gost/gost_hmac.h"
#include "gost/gost_kuznyechik.h"
#include "gost/gost_streebog.h"
#include "messages.h"
#include "peer.h"
#include "ratelimiter.h"
#include "timers.h"

#include <crypto/utils.h>
#include <net/ipv6.h>

void wg_cookie_checker_init(struct cookie_checker *checker, struct wg_device *wg)
{
	init_rwsem(&checker->secret_lock);
	checker->secret_birthdate = ktime_get_coarse_boottime_ns();
	get_random_bytes(checker->secret, NOISE_HASH_LEN);
	checker->device = wg;
}

enum
{
	COOKIE_KEY_LABEL_LEN = 8
};
static const u8 mac1_key_label[COOKIE_KEY_LABEL_LEN] __nonstring   = "mac1----";
static const u8 cookie_key_label[COOKIE_KEY_LABEL_LEN] __nonstring = "cookie--";

/*
 * WireGuard: Key = Blake2s(Label || PubKey)
 * WireGost:  Key = Streebog256(Label || PubKey)
 */
static void precompute_key(u8 key[NOISE_SYMMETRIC_KEY_LEN], const u8 pubkey[NOISE_PUBLIC_KEY_LEN], const u8 label[COOKIE_KEY_LABEL_LEN])
{
	struct gost_streebog_state ctx;

	gost_streebog256_init(&ctx);
	gost_streebog256_update(&ctx, label, COOKIE_KEY_LABEL_LEN);
	gost_streebog256_update(&ctx, pubkey, NOISE_PUBLIC_KEY_LEN);
	gost_streebog256_final(&ctx, key);

	memzero_explicit(&ctx, sizeof(ctx));
}

/* Must hold peer->handshake.static_identity->lock */
void wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker)
{
	if (likely(checker->device->static_identity.has_identity))
	{
		precompute_key(checker->cookie_encryption_key, checker->device->static_identity.static_public, cookie_key_label);
		precompute_key(checker->message_mac1_key, checker->device->static_identity.static_public, mac1_key_label);
	}
	else
	{
		memset(checker->cookie_encryption_key, 0, NOISE_SYMMETRIC_KEY_LEN);
		memset(checker->message_mac1_key, 0, NOISE_SYMMETRIC_KEY_LEN);
	}
}

void wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer)
{
	precompute_key(peer->latest_cookie.cookie_decryption_key, peer->handshake.remote_static, cookie_key_label);
	precompute_key(peer->latest_cookie.message_mac1_key, peer->handshake.remote_static, mac1_key_label);
}

void wg_cookie_init(struct cookie *cookie)
{
	memset(cookie, 0, sizeof(*cookie));
	init_rwsem(&cookie->lock);
}

/*
 * WireGuard: Keyed Blake2s
 * WireGost:  HMAC-Streebog256
 */
static void compute_mac1(u8 mac1[COOKIE_LEN], const void *message, size_t len, const u8 key[NOISE_SYMMETRIC_KEY_LEN])
{
	len = len - sizeof(struct message_macs) + offsetof(struct message_macs, mac1);
	gost_hmac256(mac1, message, len, key, NOISE_SYMMETRIC_KEY_LEN);
}

static void compute_mac2(u8 mac2[COOKIE_LEN], const void *message, size_t len, const u8 cookie[COOKIE_LEN])
{
	len = len - sizeof(struct message_macs) + offsetof(struct message_macs, mac2);
	gost_hmac256(mac2, message, len, cookie, COOKIE_LEN);
}

static void make_cookie(u8 cookie[COOKIE_LEN], struct sk_buff *skb, struct cookie_checker *checker)
{
	/*
	 * Max size needed: IPv6 (16) + Port (2) = 18 bytes.
	 * IPv4 (4) + Port (2) = 6 bytes.
	 */
	u8	   data[18];
	size_t len = 0;

	if (wg_birthdate_has_expired(checker->secret_birthdate, COOKIE_SECRET_MAX_AGE))
	{
		down_write(&checker->secret_lock);
		checker->secret_birthdate = ktime_get_coarse_boottime_ns();
		get_random_bytes(checker->secret, NOISE_HASH_LEN);
		up_write(&checker->secret_lock);
	}

	down_read(&checker->secret_lock);

	/* Construct data buffer for HMAC */
	if (skb->protocol == htons(ETH_P_IP))
	{
		memcpy(data, (u8 *)&ip_hdr(skb)->saddr, sizeof(struct in_addr));
		len += sizeof(struct in_addr);
	}
	else if (skb->protocol == htons(ETH_P_IPV6))
	{
		memcpy(data, (u8 *)&ipv6_hdr(skb)->saddr, sizeof(struct in6_addr));
		len += sizeof(struct in6_addr);
	}

	memcpy(data + len, (u8 *)&udp_hdr(skb)->source, sizeof(__be16));
	len += sizeof(__be16);

	/* HMAC-Streebog256(Key=Secret, Data=IP||Port) */
	gost_hmac256(cookie, data, len, checker->secret, NOISE_HASH_LEN);

	up_read(&checker->secret_lock);
	memzero_explicit(data, sizeof(data));
}

enum cookie_mac_state wg_cookie_validate_packet(struct cookie_checker *checker, struct sk_buff *skb, bool check_cookie)
{
	struct message_macs	 *macs = (struct message_macs *)(skb->data + skb->len - sizeof(*macs));
	enum cookie_mac_state ret;
	u8					  computed_mac[COOKIE_LEN];
	u8					  cookie[COOKIE_LEN];

	ret = INVALID_MAC;
	compute_mac1(computed_mac, skb->data, skb->len, checker->message_mac1_key);
	if (crypto_memneq(computed_mac, macs->mac1, COOKIE_LEN))
		goto out;

	ret = VALID_MAC_BUT_NO_COOKIE;

	if (!check_cookie)
		goto out;

	make_cookie(cookie, skb, checker);

	compute_mac2(computed_mac, skb->data, skb->len, cookie);
	if (crypto_memneq(computed_mac, macs->mac2, COOKIE_LEN))
		goto out;

	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	if (!wg_ratelimiter_allow(skb, dev_net(checker->device->dev)))
		goto out;

	ret = VALID_MAC_WITH_COOKIE;

out:
	return ret;
}

void wg_cookie_add_mac_to_packet(void *message, size_t len, struct wg_peer *peer)
{
	struct message_macs *macs = (struct message_macs *)((u8 *)message + len - sizeof(*macs));

	down_write(&peer->latest_cookie.lock);
	compute_mac1(macs->mac1, message, len, peer->latest_cookie.message_mac1_key);
	memcpy(peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN);
	peer->latest_cookie.have_sent_mac1 = true;
	up_write(&peer->latest_cookie.lock);

	down_read(&peer->latest_cookie.lock);
	if (peer->latest_cookie.is_valid && !wg_birthdate_has_expired(peer->latest_cookie.birthdate, COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
		compute_mac2(macs->mac2, message, len, peer->latest_cookie.cookie);
	else
		memset(macs->mac2, 0, COOKIE_LEN);
	up_read(&peer->latest_cookie.lock);
}

void wg_cookie_message_create(struct message_handshake_cookie *dst, struct sk_buff *skb, __le32 index, struct cookie_checker *checker)
{
	struct message_macs			  *macs = (struct message_macs *)((u8 *)skb->data + skb->len - sizeof(*macs));
	u8							   cookie[COOKIE_LEN];
	struct gost_kuznyechik_mgm_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));

	dst->header.type	= cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE);
	dst->receiver_index = index;

	/*
	 * Generate Nonce.
	 * WireGuard uses 24 bytes (XChaCha). Kuznyechik MGM uses 16 bytes.
	 * We generate random data for the full field but use only first 16 bytes.
	 */
	get_random_bytes_wait(dst->nonce, COOKIE_NONCE_LEN);

	make_cookie(cookie, skb, checker);

	/* Initialize MGM context */
	if (gost_kuznyechik_mgm_set_key(&ctx, checker->cookie_encryption_key) == 0)
	{
		/* Encrypt. mac1 is used as Associated Data (AD) */
		/* dst->encrypted_cookie must hold Plaintext + Tag (16 bytes) */
		gost_kuznyechik_mgm_encrypt(&ctx, dst->encrypted_cookie, cookie, COOKIE_LEN, macs->mac1, COOKIE_LEN, /* AD */
									dst->nonce																 /* IV: First 16 bytes */
		);

		gost_kuznyechik_mgm_free_ctx(&ctx);
	}
	else
	{
		pr_err("WireGost: failed to set key for cookie encryption\n");
		memset(dst->encrypted_cookie, 0, sizeof(dst->encrypted_cookie));
	}

	memzero_explicit(cookie, COOKIE_LEN);
}

void wg_cookie_message_consume(struct message_handshake_cookie *src, struct wg_device *wg)
{
	struct wg_peer				  *peer = NULL;
	u8							   cookie[COOKIE_LEN];
	int							   ret = -1;
	struct gost_kuznyechik_mgm_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));

	if (unlikely(!wg_index_hashtable_lookup(wg->index_hashtable, INDEX_HASHTABLE_HANDSHAKE | INDEX_HASHTABLE_KEYPAIR, src->receiver_index, &peer)))
		return;

	down_read(&peer->latest_cookie.lock);
	if (unlikely(!peer->latest_cookie.have_sent_mac1))
	{
		up_read(&peer->latest_cookie.lock);
		goto out;
	}

	if (gost_kuznyechik_mgm_set_key(&ctx, peer->latest_cookie.cookie_decryption_key) == 0)
	{
		/* Decrypt. mac1 (last sent) is AD */
		ret = gost_kuznyechik_mgm_decrypt(&ctx, cookie, src->encrypted_cookie, sizeof(src->encrypted_cookie), peer->latest_cookie.last_mac1_sent,
										  COOKIE_LEN, src->nonce);

		gost_kuznyechik_mgm_free_ctx(&ctx);
	}

	up_read(&peer->latest_cookie.lock);

	if (ret == 0)
	{
		down_write(&peer->latest_cookie.lock);
		memcpy(peer->latest_cookie.cookie, cookie, COOKIE_LEN);
		peer->latest_cookie.birthdate	   = ktime_get_coarse_boottime_ns();
		peer->latest_cookie.is_valid	   = true;
		peer->latest_cookie.have_sent_mac1 = false;
		up_write(&peer->latest_cookie.lock);
	}
	else
	{
		net_dbg_ratelimited("%s: Could not decrypt invalid cookie response\n", wg->dev->name);
	}

	memzero_explicit(cookie, COOKIE_LEN);

out:
	wg_peer_put(peer);
}
