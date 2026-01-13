// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2025-2026 Chudnikov A. A. <admin@redline-software.xyz>. All Rights Reserved.
 */

#include "noise.h"

#include "device.h"
#include "messages.h"
#include "peer.h"
#include "peerlookup.h"
#include "queueing.h"

#include <crypto/utils.h>
#include <linux/bitmap.h>
#include <linux/highmem.h>
#include <linux/rcupdate.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
/* This implements Noise_IKpsk2 with GOST algorithms:
 *
 * Handshake:
 *   Hash: Streebog-256
 *   DH:   VKO GOST R 34.10-2012 (512 bit)
 *   Cipher: Kuznyechik-MGM
 *   KDF:  HKDF on Streebog-256
 */

static const u8	  handshake_name[] __nonstring	= "Noise_IKpsk2_GOST_EC512_KuznyechikMGM_Streebog256";
static const u8	  identifier_name[] __nonstring = "WireGost v0.5.7 (BlueLine Software)";
static u8		  handshake_init_hash[NOISE_HASH_LEN] __ro_after_init;
static u8		  handshake_init_chaining_key[NOISE_HASH_LEN] __ro_after_init;
static atomic64_t keypair_counter = ATOMIC64_INIT(0);

void __init wg_noise_init(void)
{
	struct gost_streebog_state ctx;
	gost_streebog256(handshake_init_chaining_key, handshake_name, sizeof(handshake_name) - 1);
	gost_streebog256_init(&ctx);
	gost_streebog256_update(&ctx, handshake_init_chaining_key, NOISE_HASH_LEN);
	gost_streebog256_update(&ctx, identifier_name, sizeof(identifier_name));
	gost_streebog256_final(&ctx, handshake_init_hash);
}

void wg_noise_precompute_static_static(struct wg_peer *peer)
{
	u8 ukm[8] = {0};
	down_write(&peer->handshake.lock);
	if (!peer->handshake.static_identity->has_identity ||
		!gost_ec256_dh(peer->handshake.precomputed_static_static, peer->handshake.static_identity->static_private, peer->handshake.remote_static,
					   ukm, 8))
		memset(peer->handshake.precomputed_static_static, 0, NOISE_SYMMETRIC_KEY_LEN);
	up_write(&peer->handshake.lock);
}

void wg_noise_handshake_init(struct noise_handshake		  *handshake,
							 struct noise_static_identity *static_identity,
							 const u8					   peer_public_key[NOISE_PUBLIC_KEY_LEN],
							 const u8					   peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN],
							 struct wg_peer				  *peer)
{
	memset(handshake, 0, sizeof(*handshake));
	init_rwsem(&handshake->lock);
	handshake->entry.type = INDEX_HASHTABLE_HANDSHAKE;
	handshake->entry.peer = peer;
	memcpy(handshake->remote_static, peer_public_key, NOISE_PUBLIC_KEY_LEN);
	if (peer_preshared_key)
		memcpy(handshake->preshared_key, peer_preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	handshake->static_identity = static_identity;
	handshake->state		   = HANDSHAKE_ZEROED;
	wg_noise_precompute_static_static(peer);
}

static void handshake_zero(struct noise_handshake *handshake)
{
	memset(&handshake->ephemeral_private, 0, GOST_EC256_KEY_LEN);
	memset(&handshake->remote_ephemeral, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->hash, 0, NOISE_HASH_LEN);
	memset(&handshake->chaining_key, 0, NOISE_HASH_LEN);
	handshake->remote_index = 0;
	handshake->state		= HANDSHAKE_ZEROED;
}

void wg_noise_handshake_clear(struct noise_handshake *handshake)
{
	down_write(&handshake->lock);
	wg_index_hashtable_remove(handshake->entry.peer->device->index_hashtable, &handshake->entry);
	handshake_zero(handshake);
	up_write(&handshake->lock);
}

static struct noise_keypair *keypair_create(struct wg_peer *peer)
{
	struct noise_keypair *keypair = kzalloc(sizeof(*keypair), GFP_KERNEL);
	if (unlikely(!keypair))
		return NULL;
	spin_lock_init(&keypair->receiving_counter.lock);
	keypair->internal_id = atomic64_inc_return(&keypair_counter);
	keypair->entry.type	 = INDEX_HASHTABLE_KEYPAIR;
	keypair->entry.peer	 = peer;
	kref_init(&keypair->refcount);
	return keypair;
}

static void keypair_free_rcu(struct rcu_head *rcu)
{
	struct noise_keypair *keypair = container_of(rcu, struct noise_keypair, rcu);
	gost_kuznyechik_mgm_free_ctx(&keypair->sending.mgm_ctx);
	gost_kuznyechik_mgm_free_ctx(&keypair->receiving.mgm_ctx);
	kfree_sensitive(keypair);
}

static void keypair_free_kref(struct kref *kref)
{
	struct noise_keypair *keypair = container_of(kref, struct noise_keypair, refcount);
	net_dbg_ratelimited("%s: Keypair %llu destroyed for peer %llu\n", keypair->entry.peer->device->dev->name, keypair->internal_id,
						keypair->entry.peer->internal_id);
	wg_index_hashtable_remove(keypair->entry.peer->device->index_hashtable, &keypair->entry);
	call_rcu(&keypair->rcu, keypair_free_rcu);
}

void wg_noise_keypair_put(struct noise_keypair *keypair, bool unreference_now)
{
	if (unlikely(!keypair))
		return;
	if (unlikely(unreference_now))
		wg_index_hashtable_remove(keypair->entry.peer->device->index_hashtable, &keypair->entry);
	kref_put(&keypair->refcount, keypair_free_kref);
}

struct noise_keypair *wg_noise_keypair_get(struct noise_keypair *keypair)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(), "Taking noise keypair reference without holding the RCU BH read lock");
	if (unlikely(!keypair || !kref_get_unless_zero(&keypair->refcount)))
		return NULL;
	return keypair;
}

void wg_noise_keypairs_clear(struct noise_keypairs *keypairs)
{
	struct noise_keypair *old;
	spin_lock_bh(&keypairs->keypair_update_lock);
	old = rcu_dereference_protected(keypairs->next_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->next_keypair, NULL);
	wg_noise_keypair_put(old, true);
	old = rcu_dereference_protected(keypairs->previous_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->previous_keypair, NULL);
	wg_noise_keypair_put(old, true);
	old = rcu_dereference_protected(keypairs->current_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	RCU_INIT_POINTER(keypairs->current_keypair, NULL);
	wg_noise_keypair_put(old, true);
	spin_unlock_bh(&keypairs->keypair_update_lock);
}

void wg_noise_expire_current_peer_keypairs(struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	wg_noise_handshake_clear(&peer->handshake);
	wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
	spin_lock_bh(&peer->keypairs.keypair_update_lock);
	keypair = rcu_dereference_protected(peer->keypairs.next_keypair, lockdep_is_held(&peer->keypairs.keypair_update_lock));
	if (keypair)
		keypair->sending.is_valid = false;
	keypair = rcu_dereference_protected(peer->keypairs.current_keypair, lockdep_is_held(&peer->keypairs.keypair_update_lock));
	if (keypair)
		keypair->sending.is_valid = false;
	spin_unlock_bh(&peer->keypairs.keypair_update_lock);
}

static void add_new_keypair(struct noise_keypairs *keypairs, struct noise_keypair *new_keypair)
{
	struct noise_keypair *previous_keypair, *next_keypair, *current_keypair;
	spin_lock_bh(&keypairs->keypair_update_lock);
	previous_keypair = rcu_dereference_protected(keypairs->previous_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	next_keypair	 = rcu_dereference_protected(keypairs->next_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	current_keypair	 = rcu_dereference_protected(keypairs->current_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	if (new_keypair->i_am_the_initiator)
	{
		if (next_keypair)
		{
			RCU_INIT_POINTER(keypairs->next_keypair, NULL);
			rcu_assign_pointer(keypairs->previous_keypair, next_keypair);
			wg_noise_keypair_put(current_keypair, true);
		}
		else
			rcu_assign_pointer(keypairs->previous_keypair, current_keypair);
		wg_noise_keypair_put(previous_keypair, true);
		rcu_assign_pointer(keypairs->current_keypair, new_keypair);
	}
	else
	{
		rcu_assign_pointer(keypairs->next_keypair, new_keypair);
		wg_noise_keypair_put(next_keypair, true);
		RCU_INIT_POINTER(keypairs->previous_keypair, NULL);
		wg_noise_keypair_put(previous_keypair, true);
	}
	spin_unlock_bh(&keypairs->keypair_update_lock);
}

bool wg_noise_received_with_keypair(struct noise_keypairs *keypairs, struct noise_keypair *received_keypair)
{
	struct noise_keypair *old_keypair;
	bool				  key_is_new;
	key_is_new = received_keypair == rcu_access_pointer(keypairs->next_keypair);
	if (likely(!key_is_new))
		return false;
	spin_lock_bh(&keypairs->keypair_update_lock);
	if (unlikely(received_keypair != rcu_dereference_protected(keypairs->next_keypair, lockdep_is_held(&keypairs->keypair_update_lock))))
	{
		spin_unlock_bh(&keypairs->keypair_update_lock);
		return false;
	}
	old_keypair = rcu_dereference_protected(keypairs->previous_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	rcu_assign_pointer(keypairs->previous_keypair,
					   rcu_dereference_protected(keypairs->current_keypair, lockdep_is_held(&keypairs->keypair_update_lock)));
	wg_noise_keypair_put(old_keypair, true);
	rcu_assign_pointer(keypairs->current_keypair, received_keypair);
	RCU_INIT_POINTER(keypairs->next_keypair, NULL);
	spin_unlock_bh(&keypairs->keypair_update_lock);
	return true;
}

void wg_noise_set_static_identity_private_key(struct noise_static_identity *static_identity, const u8 private_key[GOST_EC256_KEY_LEN])
{
	memcpy(static_identity->static_private, private_key, GOST_EC256_KEY_LEN);

	if (gost_ec256_generate_public_key(static_identity->static_public, private_key))
	{
		static_identity->has_identity = true;
	}
	else
	{
		static_identity->has_identity = false;
		memset(static_identity->static_public, 0, NOISE_PUBLIC_KEY_LEN);
		pr_err("WireGost: Failed to generate public key from private key!\n");
	}
}

static void kdf(u8		 *first_dst,
				u8		 *second_dst,
				u8		 *third_dst,
				const u8 *data,
				size_t	  first_len,
				size_t	  second_len,
				size_t	  third_len,
				size_t	  data_len,
				const u8  chaining_key[NOISE_HASH_LEN])
{
	u8 output[NOISE_HASH_LEN + 1];
	u8 secret[NOISE_HASH_LEN];
	WARN_ON(IS_ENABLED(DEBUG) && (first_len > NOISE_HASH_LEN || second_len > NOISE_HASH_LEN || third_len > NOISE_HASH_LEN ||
								  ((second_len || second_dst || third_len || third_dst) && (!first_len || !first_dst)) ||
								  ((third_len || third_dst) && (!second_len || !second_dst))));
	gost_hmac256(secret, data, data_len, chaining_key, NOISE_HASH_LEN);
	if (!first_dst || !first_len)
		goto out;
	output[0] = 1;
	gost_hmac256(output, output, 1, secret, NOISE_HASH_LEN);
	memcpy(first_dst, output, first_len);
	if (!second_dst || !second_len)
		goto out;
	output[NOISE_HASH_LEN] = 2;
	gost_hmac256(output, output, NOISE_HASH_LEN + 1, secret, NOISE_HASH_LEN);
	memcpy(second_dst, output, second_len);
	if (!third_dst || !third_len)
		goto out;
	output[NOISE_HASH_LEN] = 3;
	gost_hmac256(output, output, NOISE_HASH_LEN + 1, secret, NOISE_HASH_LEN);
	memcpy(third_dst, output, third_len);
out:
	memzero_explicit(secret, NOISE_HASH_LEN);
	memzero_explicit(output, NOISE_HASH_LEN + 1);
}

static void derive_keys(struct noise_symmetric_key *first_dst, struct noise_symmetric_key *second_dst, const u8 chaining_key[NOISE_HASH_LEN])
{
	u64 birthdate = ktime_get_coarse_boottime_ns();
	kdf(first_dst->key, second_dst->key, NULL, NULL, NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0, chaining_key);
	if (gost_kuznyechik_mgm_set_key(&first_dst->mgm_ctx, first_dst->key) != 0)
		pr_err("WireGost: failed to set sending key\n");
	if (gost_kuznyechik_mgm_set_key(&second_dst->mgm_ctx, second_dst->key) != 0)
		pr_err("WireGost: failed to set receiving key\n");
	first_dst->birthdate = second_dst->birthdate = birthdate;
	first_dst->is_valid = second_dst->is_valid = true;
}

static bool __must_check mix_dh(u8		 chaining_key[NOISE_HASH_LEN],
								u8		 key[NOISE_SYMMETRIC_KEY_LEN],
								const u8 private[GOST_EC256_KEY_LEN],
								const u8 public[NOISE_PUBLIC_KEY_LEN])
{
	u8	dh_calculation[NOISE_SYMMETRIC_KEY_LEN];
	u8 *ukm = chaining_key;
	if (unlikely(!gost_ec256_dh(dh_calculation, private, public, ukm, 8)))
		return false;
	kdf(chaining_key, key, NULL, dh_calculation, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	memzero_explicit(dh_calculation, NOISE_SYMMETRIC_KEY_LEN);
	return true;
}

static bool __must_check mix_precomputed_dh(u8		 chaining_key[NOISE_HASH_LEN],
											u8		 key[NOISE_SYMMETRIC_KEY_LEN],
											const u8 precomputed[NOISE_SYMMETRIC_KEY_LEN])
{
	static u8 zero_point[NOISE_SYMMETRIC_KEY_LEN];
	if (unlikely(!crypto_memneq(precomputed, zero_point, NOISE_SYMMETRIC_KEY_LEN)))
		return false;
	kdf(chaining_key, key, NULL, precomputed, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	return true;
}

static void mix_hash(u8 hash[NOISE_HASH_LEN], const u8 *src, size_t src_len)
{
	struct gost_streebog_state ctx;
	gost_streebog256_init(&ctx);
	gost_streebog256_update(&ctx, hash, NOISE_HASH_LEN);
	gost_streebog256_update(&ctx, src, src_len);
	gost_streebog256_final(&ctx, hash);
}

static void
mix_psk(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN], const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	u8 temp_hash[NOISE_HASH_LEN];
	kdf(chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	mix_hash(hash, temp_hash, NOISE_HASH_LEN);
	memzero_explicit(temp_hash, NOISE_HASH_LEN);
}

static void handshake_init(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN], const u8 remote_static[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	mix_hash(hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static void message_encrypt(u8 *dst_ciphertext, const u8 *src_plaintext, size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN])
{
	u8							   nonce[16] = {0};
	struct gost_kuznyechik_mgm_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	if (likely(gost_kuznyechik_mgm_set_key(&ctx, key) == 0))
	{
		gost_kuznyechik_mgm_encrypt(&ctx, dst_ciphertext, src_plaintext, src_len, hash, NOISE_HASH_LEN, nonce);
		gost_kuznyechik_mgm_free_ctx(&ctx);
	}
	mix_hash(hash, dst_ciphertext, noise_encrypted_len(src_len));
}

static bool message_decrypt(u8 *dst_plaintext, const u8 *src_ciphertext, size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN])
{
	u8							   nonce[16] = {0};
	bool						   ret		 = false;
	struct gost_kuznyechik_mgm_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	if (likely(gost_kuznyechik_mgm_set_key(&ctx, key) == 0))
	{
		if (gost_kuznyechik_mgm_decrypt(&ctx, dst_plaintext, src_ciphertext, src_len, hash, NOISE_HASH_LEN, nonce) == 0)
		{
			ret = true;
		}
		gost_kuznyechik_mgm_free_ctx(&ctx);
	}
	if (!ret)
		return false;
	mix_hash(hash, src_ciphertext, src_len);
	return true;
}

static void message_ephemeral(u8	   ephemeral_dst[NOISE_PUBLIC_KEY_LEN],
							  const u8 ephemeral_src[NOISE_PUBLIC_KEY_LEN],
							  u8	   chaining_key[NOISE_HASH_LEN],
							  u8	   hash[NOISE_HASH_LEN])
{
	if (ephemeral_dst != ephemeral_src)
		memcpy(ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	mix_hash(hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	kdf(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
}

static void tai64n_now(u8 output[NOISE_TIMESTAMP_LEN])
{
	struct timespec64 now;
	ktime_get_real_ts64(&now);
	now.tv_nsec							 = ALIGN_DOWN(now.tv_nsec, rounddown_pow_of_two(NSEC_PER_SEC / INITIATIONS_PER_SECOND));
	*(__be64 *)output					 = cpu_to_be64(0x400000000000000aULL + now.tv_sec);
	*(__be32 *)(output + sizeof(__be64)) = cpu_to_be32(now.tv_nsec);
}

bool wg_noise_handshake_create_initiation(struct message_handshake_initiation *dst, struct noise_handshake *handshake)
{
	u8	 timestamp[NOISE_TIMESTAMP_LEN];
	u8	 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;
	wait_for_random_bytes();
	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);
	if (unlikely(!handshake->static_identity->has_identity))
		goto out;
	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);
	handshake_init(handshake->chaining_key, handshake->hash, handshake->remote_static);
	if (!gost_ec256_generate_private_key(handshake->ephemeral_private))
		goto out;
	if (!gost_ec256_generate_public_key(dst->unencrypted_ephemeral, handshake->ephemeral_private))
		goto out;
	message_ephemeral(dst->unencrypted_ephemeral, dst->unencrypted_ephemeral, handshake->chaining_key, handshake->hash);
	if (!mix_dh(handshake->chaining_key, key, handshake->ephemeral_private, handshake->remote_static))
		goto out;
	message_encrypt(dst->encrypted_static, handshake->static_identity->static_public, NOISE_PUBLIC_KEY_LEN, key, handshake->hash);
	if (!mix_precomputed_dh(handshake->chaining_key, key, handshake->precomputed_static_static))
		goto out;
	tai64n_now(timestamp);
	message_encrypt(dst->encrypted_timestamp, timestamp, NOISE_TIMESTAMP_LEN, key, handshake->hash);
	dst->sender_index = wg_index_hashtable_insert(handshake->entry.peer->device->index_hashtable, &handshake->entry);
	handshake->state  = HANDSHAKE_CREATED_INITIATION;
	ret				  = true;
out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	return ret;
}

struct wg_peer *wg_noise_handshake_consume_initiation(struct message_handshake_initiation *src, struct wg_device *wg)
{
	struct wg_peer		   *peer = NULL, *ret_peer = NULL;
	struct noise_handshake *handshake;
	bool					replay_attack, flood_attack;
	u8						key[NOISE_SYMMETRIC_KEY_LEN];
	u8						chaining_key[NOISE_HASH_LEN];
	u8						hash[NOISE_HASH_LEN];
	u8						s[NOISE_PUBLIC_KEY_LEN];
	u8						e[NOISE_PUBLIC_KEY_LEN];
	u8						t[NOISE_TIMESTAMP_LEN];
	u64						initiation_consumption;
	down_read(&wg->static_identity.lock);
	if (unlikely(!wg->static_identity.has_identity))
		goto out;
	handshake_init(chaining_key, hash, wg->static_identity.static_public);
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);
	if (!mix_dh(chaining_key, key, wg->static_identity.static_private, e))
		goto out;
	if (!message_decrypt(s, src->encrypted_static, sizeof(src->encrypted_static), key, hash))
		goto out;
	peer = wg_pubkey_hashtable_lookup(wg->peer_hashtable, s);
	if (!peer)
		goto out;
	handshake = &peer->handshake;
	if (!mix_precomputed_dh(chaining_key, key, handshake->precomputed_static_static))
		goto out;
	if (!message_decrypt(t, src->encrypted_timestamp, sizeof(src->encrypted_timestamp), key, hash))
		goto out;
	down_read(&handshake->lock);
	replay_attack = memcmp(t, handshake->latest_timestamp, NOISE_TIMESTAMP_LEN) <= 0;
	flood_attack  = (s64)handshake->last_initiation_consumption + NSEC_PER_SEC / INITIATIONS_PER_SECOND > (s64)ktime_get_coarse_boottime_ns();
	up_read(&handshake->lock);
	if (replay_attack || flood_attack)
		goto out;
	down_write(&handshake->lock);
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	if (memcmp(t, handshake->latest_timestamp, NOISE_TIMESTAMP_LEN) > 0)
		memcpy(handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	handshake->remote_index = src->sender_index;
	initiation_consumption	= ktime_get_coarse_boottime_ns();
	if ((s64)(handshake->last_initiation_consumption - initiation_consumption) < 0)
		handshake->last_initiation_consumption = initiation_consumption;
	handshake->state = HANDSHAKE_CONSUMED_INITIATION;
	up_write(&handshake->lock);
	ret_peer = peer;
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	up_read(&wg->static_identity.lock);
	if (!ret_peer)
		wg_peer_put(peer);
	return ret_peer;
}

bool wg_noise_handshake_create_response(struct message_handshake_response *dst, struct noise_handshake *handshake)
{
	u8	 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;
	wait_for_random_bytes();
	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);
	if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
		goto out;
	dst->header.type	= cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE);
	dst->receiver_index = handshake->remote_index;
	if (!gost_ec256_generate_private_key(handshake->ephemeral_private))
		goto out;
	if (!gost_ec256_generate_public_key(dst->unencrypted_ephemeral, handshake->ephemeral_private))
		goto out;
	message_ephemeral(dst->unencrypted_ephemeral, dst->unencrypted_ephemeral, handshake->chaining_key, handshake->hash);
	if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private, handshake->remote_ephemeral))
		goto out;
	if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private, handshake->remote_static))
		goto out;
	mix_psk(handshake->chaining_key, handshake->hash, key, handshake->preshared_key);
	message_encrypt(dst->encrypted_nothing, NULL, 0, key, handshake->hash);
	dst->sender_index = wg_index_hashtable_insert(handshake->entry.peer->device->index_hashtable, &handshake->entry);
	handshake->state  = HANDSHAKE_CREATED_RESPONSE;
	ret				  = true;
out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	return ret;
}

struct wg_peer *wg_noise_handshake_consume_response(struct message_handshake_response *src, struct wg_device *wg)
{
	enum noise_handshake_state state = HANDSHAKE_ZEROED;
	struct wg_peer			  *peer = NULL, *ret_peer = NULL;
	struct noise_handshake	  *handshake;
	u8						   key[NOISE_SYMMETRIC_KEY_LEN];
	u8						   hash[NOISE_HASH_LEN];
	u8						   chaining_key[NOISE_HASH_LEN];
	u8						   e[NOISE_PUBLIC_KEY_LEN];
	u8						   ephemeral_private[GOST_EC256_KEY_LEN];
	u8						   preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	down_read(&wg->static_identity.lock);
	if (unlikely(!wg->static_identity.has_identity))
		goto out;
	handshake = (struct noise_handshake *)wg_index_hashtable_lookup(wg->index_hashtable, INDEX_HASHTABLE_HANDSHAKE, src->receiver_index, &peer);
	if (unlikely(!handshake))
		goto out;
	down_read(&handshake->lock);
	state = handshake->state;
	memcpy(hash, handshake->hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
	memcpy(ephemeral_private, handshake->ephemeral_private, GOST_EC256_KEY_LEN);
	memcpy(preshared_key, handshake->preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	up_read(&handshake->lock);
	if (state != HANDSHAKE_CREATED_INITIATION)
		goto fail;
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);
	if (!mix_dh(chaining_key, NULL, ephemeral_private, e))
		goto fail;
	if (!mix_dh(chaining_key, NULL, wg->static_identity.static_private, e))
		goto fail;
	mix_psk(chaining_key, hash, key, preshared_key);
	if (!message_decrypt(NULL, src->encrypted_nothing, sizeof(src->encrypted_nothing), key, hash))
		goto fail;
	down_write(&handshake->lock);
	if (handshake->state != state)
	{
		up_write(&handshake->lock);
		goto fail;
	}
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	handshake->remote_index = src->sender_index;
	handshake->state		= HANDSHAKE_CONSUMED_RESPONSE;
	up_write(&handshake->lock);
	ret_peer = peer;
	goto out;
fail:
	wg_peer_put(peer);
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	memzero_explicit(ephemeral_private, GOST_EC256_KEY_LEN);
	memzero_explicit(preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	up_read(&wg->static_identity.lock);
	return ret_peer;
}

bool wg_noise_handshake_begin_session(struct noise_handshake *handshake, struct noise_keypairs *keypairs)
{
	struct noise_keypair *new_keypair;
	bool				  ret = false;
	down_write(&handshake->lock);
	if (handshake->state != HANDSHAKE_CREATED_RESPONSE && handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
		goto out;
	new_keypair = keypair_create(handshake->entry.peer);
	if (!new_keypair)
		goto out;
	new_keypair->i_am_the_initiator = handshake->state == HANDSHAKE_CONSUMED_RESPONSE;
	new_keypair->remote_index		= handshake->remote_index;
	if (new_keypair->i_am_the_initiator)
		derive_keys(&new_keypair->sending, &new_keypair->receiving, handshake->chaining_key);
	else
		derive_keys(&new_keypair->receiving, &new_keypair->sending, handshake->chaining_key);
	handshake_zero(handshake);
	rcu_read_lock_bh();
	if (likely(!READ_ONCE(container_of(handshake, struct wg_peer, handshake)->is_dead)))
	{
		add_new_keypair(keypairs, new_keypair);
		net_dbg_ratelimited("%s: Keypair %llu created for peer %llu\n", handshake->entry.peer->device->dev->name, new_keypair->internal_id,
							handshake->entry.peer->internal_id);
		ret = wg_index_hashtable_replace(handshake->entry.peer->device->index_hashtable, &handshake->entry, &new_keypair->entry);
	}
	else
	{
		kfree_sensitive(new_keypair);
	}
	rcu_read_unlock_bh();
out:
	up_write(&handshake->lock);
	return ret;
}
