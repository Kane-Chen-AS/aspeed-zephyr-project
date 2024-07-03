/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <stdio.h>

#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMContext.h"
#include "SPDM/SPDMKeyOperation.h"

#include <mbedtls/sha512.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>

LOG_MODULE_REGISTER(spdm_key, CONFIG_LOG_DEFAULT_LEVEL);

void spdm_hexdump_helper(void *in, int len, const char *pre)
{
	uint8_t *ptr = in;
	int first = 1, size;
	char *tmp = NULL;

	size = strlen(pre) + 6; // 6 bytes for " cont" and null-end
	if (size > 64) {
		LOG_ERR("Invalid messages size (%d), ignored", size);
		return;
	}

	tmp = malloc(size);
	if (tmp == NULL) {
		LOG_ERR("Failed to allocate for hexdump buffer");
		return;
	}

	while (len > 0) {
		if (first) {
			first = 0;
			snprintf(tmp, size, "%s", pre);
		} else
			snprintf(tmp, size, "%s cont", pre);

		if (len > SPDM_HEXDUMP_SIZE)
			LOG_HEXDUMP_INF(ptr, SPDM_HEXDUMP_SIZE, tmp);
		else
			LOG_HEXDUMP_INF(ptr, len, tmp);

		len -= SPDM_HEXDUMP_SIZE;
		ptr += SPDM_HEXDUMP_SIZE;
	}
	free(tmp);
}

size_t spdm_get_md_block_size(const mbedtls_md_info_t *md_info)
{
	switch (mbedtls_md_get_type(md_info)) {
	case MBEDTLS_MD_SHA256:
		return 64;
	case MBEDTLS_MD_SHA384:
	case MBEDTLS_MD_SHA512:
		return 128;
	default:
		LOG_ERR("Type %d is not supported", mbedtls_md_get_type(md_info));
	}
	return 0;
}

/*
 * mbedtls_md_clone function can't provide an expected functionality as code needed
 * because all members in mbedtls_md_context_t are pointers and mbedtls_md_clone only
 * make the DST to point to the same space as the SRC.
 * To implement spdm_hmac_clone for copying all member data.
 */
int spdm_hmac_clone(mbedtls_md_context_t *dst, mbedtls_md_context_t *src)
{
	if (dst == NULL || src == NULL) {
		LOG_ERR("Invalid arguments (%p, %p)", dst, src);
		return -1;
	}

	if (src->MBEDTLS_PRIVATE(md_ctx) == NULL ||
		src->MBEDTLS_PRIVATE(hmac_ctx) == NULL ||
		src->MBEDTLS_PRIVATE(md_info) == NULL) {
		uint8_t *md_ctx = (uint8_t *)src->MBEDTLS_PRIVATE(md_ctx),
				*hmac_ctx = (uint8_t *)src->MBEDTLS_PRIVATE(hmac_ctx),
				*md_info = (uint8_t *)src->MBEDTLS_PRIVATE(md_info);

		LOG_ERR("Src has invalid arguments (%p, %p, %p)", md_ctx, hmac_ctx, md_info);
		return -1;
	}

	if (dst->MBEDTLS_PRIVATE(md_ctx) == NULL ||
		dst->MBEDTLS_PRIVATE(hmac_ctx) == NULL ||
		dst->MBEDTLS_PRIVATE(md_info) == NULL) {
		uint8_t *md_ctx = (uint8_t *)dst->MBEDTLS_PRIVATE(md_ctx),
				*hmac_ctx = (uint8_t *)dst->MBEDTLS_PRIVATE(hmac_ctx),
				*md_info = (uint8_t *)dst->MBEDTLS_PRIVATE(md_info);

		LOG_ERR("Dst has invalid arguments (%p, %p, %p)", md_ctx, hmac_ctx, md_info);
		return -1;
	}

	dst->MBEDTLS_PRIVATE(md_info) = src->MBEDTLS_PRIVATE(md_info);
	memcpy(dst->MBEDTLS_PRIVATE(md_ctx), src->MBEDTLS_PRIVATE(md_ctx),
		sizeof(mbedtls_sha512_context));
	memcpy(dst->MBEDTLS_PRIVATE(hmac_ctx), src->MBEDTLS_PRIVATE(hmac_ctx),
		spdm_get_md_block_size(src->MBEDTLS_PRIVATE(md_info)) * 2);
	return 0;
}

/*
 * Requester provides a pre-defined PSK hint to Responder to map PSK data
 * User should implement a proprietary mapping rule for the pre-defined PSK hint and PSK data
 * in Requester/Responder sides. Thus, the code can finish key exchange process by using this mapping rule.
 * The below example is used to generate the same PSK data as libspdm sample code.
 */
#define DEFAULT_PSK_DATA "TestPskData"
#define DEFAULT_PSK_HINT "TestPskHint"
static int gen_psk_data(struct spdm_session_context *session, uint8_t *out, uint8_t *outlen)
{
	/* ToDo : validate the output buffer size */
	if (session == NULL || out == NULL || outlen == NULL) {
		LOG_ERR("Invalid arguments %p, %p %p", session, out, outlen);
		return -1;
	}

	if (session->secret_len == 0) {
		// to use default pre-defined PSK data
		*outlen = snprintf(out, *outlen, "%s", DEFAULT_PSK_DATA);
		(*outlen)++; // for string null-end
	} else if (memcmp(DEFAULT_PSK_HINT, session->shared_secret, session->secret_len) == 0) {
		*outlen = snprintf(out, *outlen, "%s", DEFAULT_PSK_DATA);
		(*outlen)++; // for string null-end
	} else
		return -1;

	return 0;
}

bool spdm_isCapabilitiesEnabled(struct spdm_context *context, uint32_t flag)
{
	uint32_t local_cap, remote_cap;

	local_cap = context->local.capabilities.flags;
	remote_cap = context->remote.capabilities.flags;

	LOG_DBG("Local Cap is enabled = %x", local_cap&flag);
	LOG_DBG("Remote Cap is enabled = %x", remote_cap&flag);

	if ((local_cap&flag) != (remote_cap&flag))
		return false;
	else if ((local_cap&flag) == flag)
		return true;
	else
		return false;
}

int spdm_gen_handshake_key_iv(struct spdm_context *context, struct spdm_session_context *session, uint8_t mode)
{
	if (context == NULL || session == NULL) {
		LOG_ERR("Invalid arguments, %p, %p", context, session);
		return -1;
	}

	if (mode == SPDM_REQUEST_MODE) {
		if (spdm_gen_key_iv(context, session->master_secret_req,
				session->encryption_key_req,
				sizeof(session->encryption_key_req),
				session->encryption_salt_req,
				sizeof(session->encryption_salt_req)))
			return -1;

		SPDM_DBG_HEXDUMP(session->encryption_key_req, sizeof(session->encryption_key_req),
			"Handshake key (req)");
		SPDM_DBG_HEXDUMP(session->encryption_salt_req, sizeof(session->encryption_salt_req),
			"Handshake salt (req)");
	} else {
		if (spdm_gen_key_iv(context, session->master_secret_rsp,
				session->encryption_key_rsp,
				sizeof(session->encryption_key_rsp),
				session->encryption_salt_rsp,
				sizeof(session->encryption_salt_rsp)))
			return -1;

		SPDM_DBG_HEXDUMP(session->encryption_key_rsp, sizeof(session->encryption_key_rsp),
			"Handshake key (rsp)");
		SPDM_DBG_HEXDUMP(session->encryption_salt_rsp, sizeof(session->encryption_salt_rsp),
			"Handshake salt (rsp)");
	}

	return 0;
}

int spdm_gen_finish_key(struct spdm_context *context, struct spdm_session_context *session, uint8_t mode, uint8_t *out)
{
	uint8_t bin_str[96];
	size_t bin_size = sizeof(bin_str);
	const mbedtls_md_info_t *md_info;

	if (context == NULL || session == NULL || out == NULL) {
		LOG_ERR("Invalid arguments : %p, %p, %p", context, session, out);
		return -1;
	}

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
	spdm_bin_concat(context, SPDM_BIN_LABEL_STR_7, strlen(SPDM_BIN_LABEL_STR_7), NULL, 0,
			bin_str, &bin_size, SPDM_LABEL_MSG_LEN_7);
	SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR7");
	if (mode == SPDM_REQUEST_MODE) {
		mbedtls_hkdf_expand(md_info, session->master_secret_req, 48, bin_str,
			bin_size, out, 48);
		SPDM_DBG_HEXDUMP(out, 48, "Finished_key (req)");
	} else {
		mbedtls_hkdf_expand(md_info, session->master_secret_rsp, 48, bin_str,
			bin_size, out, 48);
		SPDM_DBG_HEXDUMP(out, 48, "Finished_key (rsp)");
	}

	return 0;
}

int spdm_gen_key_iv(struct spdm_context *context, uint8_t *master_secret, uint8_t *keyout, int key_size, uint8_t *ivout, int iv_size)
{
	uint8_t bin_str[96];
	size_t bin_size = sizeof(bin_str);
	const mbedtls_md_info_t *md_info;

	if (context == NULL || master_secret == NULL || keyout == NULL || ivout == NULL) {
		LOG_ERR("Invalid arguments : %p, %p, %p, %p", context, master_secret, keyout, ivout);
		return -1;
	}

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
	/* Generate encryption key */
	spdm_bin_concat(context, SPDM_BIN_LABEL_STR_5, strlen(SPDM_BIN_LABEL_STR_5), NULL, 0,
			bin_str, &bin_size, SPDM_LABEL_MSG_LEN_5);
	SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR5");
	mbedtls_hkdf_expand(md_info, master_secret, 48, bin_str, bin_size, keyout, key_size);

	/* Generate encrypt salt */
	memset(bin_str, 0, sizeof(bin_str));
	spdm_bin_concat(context, SPDM_BIN_LABEL_STR_6, strlen(SPDM_BIN_LABEL_STR_6), NULL, 0,
			bin_str, &bin_size, SPDM_LABEL_MSG_LEN_6);
	SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR6");
	mbedtls_hkdf_expand(md_info, master_secret, 48, bin_str, bin_size, ivout, iv_size);

	return 0;
}

int spdm_gen_session_key_iv(struct spdm_context *context, struct spdm_session_context *session, uint8_t mode, uint8_t *hash_data, bool is_psk)
{
	uint8_t bin_str[96];
	uint8_t salt1[48];
	uint8_t *session_secret;
	size_t bin_size, master_secret_size;
	const mbedtls_md_info_t *md_info;
	uint8_t *master_secret;

	if (context == NULL || session == NULL) {
		LOG_ERR("Invalid arguments, %p, %p\n", context, session);
		return -1;
	}

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
	memset(bin_str, 0, sizeof(bin_str));

	if (session->master_secret == NULL) {
		uint8_t data[64];

		master_secret = malloc(48);
		if (master_secret == NULL) {
			LOG_ERR("can't allocate memory for master secret");
			return -1;
		}

		memset(master_secret, 0, 48);
		bin_size = sizeof(bin_str);
		spdm_bin_concat(context, SPDM_BIN_LABEL_STR_0, strlen(SPDM_BIN_LABEL_STR_0),
				NULL, 0, bin_str, &bin_size, SPDM_LABEL_MSG_LEN_0);
		SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR0");
		mbedtls_hkdf_expand(md_info, session->handshake_secret, 48, bin_str, bin_size,
				salt1, sizeof(salt1));
		SPDM_DBG_HEXDUMP(salt1, 48, "Salt for master_secret");
		md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
		memset(data, 0, sizeof(data));
		mbedtls_md_hmac(md_info, salt1, 48, data, 48, master_secret);
		SPDM_DBG_HEXDUMP(master_secret, 48, "Master secret");

		session->master_secret = master_secret;
	} else
		master_secret = session->master_secret;
	master_secret_size = 48;

	memset(bin_str, 0, sizeof(bin_str));
	bin_size = sizeof(bin_str);
	if (mode == SPDM_REQUEST_MODE) {
		spdm_bin_concat(context, SPDM_BIN_LABEL_STR_3, strlen(SPDM_BIN_LABEL_STR_3),
				hash_data, 48, bin_str, &bin_size, SPDM_LABEL_MSG_LEN_3);
		SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR3");
	} else {
		spdm_bin_concat(context, SPDM_BIN_LABEL_STR_4, strlen(SPDM_BIN_LABEL_STR_4),
				hash_data, 48, bin_str, &bin_size, SPDM_LABEL_MSG_LEN_4);
		SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR4");
	}

	/* Generate session secret */
	session_secret = malloc(48);
	if (session_secret == NULL) {
		LOG_ERR("Failed to allocate memory for session secret");
		return -1;
	}

	memset(session_secret, 0, sizeof(session_secret));
	mbedtls_hkdf_expand(md_info, master_secret, master_secret_size, bin_str, bin_size,
			session_secret, 48);
	SPDM_DBG_HEXDUMP(session_secret, 48, "Session secret");

	if (mode == SPDM_REQUEST_MODE) {
		session->session_secret_req = session_secret;
		if (spdm_gen_key_iv(context, session_secret,
				session->encryption_key_req, sizeof(session->encryption_key_req),
				session->encryption_salt_req, sizeof(session->encryption_salt_req)))
			return -1;

		SPDM_DBG_HEXDUMP(session->encryption_key_req,
			sizeof(session->encryption_key_req), "Key (req)");
		SPDM_DBG_HEXDUMP(session->encryption_salt_req,
			sizeof(session->encryption_salt_req), "Salt (req)");
	} else {
		session->session_secret_rsp = session_secret;
		if (spdm_gen_key_iv(context, session_secret,
				session->encryption_key_rsp, sizeof(session->encryption_key_rsp),
				session->encryption_salt_rsp, sizeof(session->encryption_salt_rsp)))
			return -1;

		SPDM_DBG_HEXDUMP(session->encryption_key_rsp,
			sizeof(session->encryption_key_rsp), "Key (rsp)");
		SPDM_DBG_HEXDUMP(session->encryption_salt_rsp,
			sizeof(session->encryption_salt_rsp), "Salt (rsp)");
	}

	return 0;
}

int spdm_update_key(struct spdm_context *context, struct spdm_session_context *session, uint8_t mode)
{
	uint8_t bin_str[96];
	size_t bin_size = sizeof(bin_str);
	const mbedtls_md_info_t *md_info;
	uint8_t new_session_secret[48];

	if (context == NULL || session == NULL) {
		LOG_ERR("Invalid arguments, %p, %p\n", context, session);
		return -1;
	}

	LOG_INF("Update key for %s", (mode == SPDM_REQUEST_MODE)?"req":"rsp");
	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
	memset(bin_str, 0, sizeof(bin_str));
	spdm_bin_concat(context, SPDM_BIN_LABEL_STR_9, strlen(SPDM_BIN_LABEL_STR_9), NULL, 0,
			bin_str, &bin_size, SPDM_LABEL_MSG_LEN_9);
	SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR9");

	memset(new_session_secret, 0, sizeof(new_session_secret));
	if (mode == SPDM_REQUEST_MODE) {
		SPDM_DBG_HEXDUMP(session->session_secret_req, 48, "Old secret (req)");

		mbedtls_hkdf_expand(md_info, session->session_secret_req, 48, bin_str, bin_size,
				new_session_secret, sizeof(new_session_secret));
		SPDM_DBG_HEXDUMP(new_session_secret, sizeof(new_session_secret), "New secret (req)");
		memcpy(session->session_secret_req, new_session_secret, sizeof(new_session_secret));
		if (spdm_gen_key_iv(context, new_session_secret,
				session->encryption_key_req, sizeof(session->encryption_key_req),
				session->encryption_salt_req, sizeof(session->encryption_salt_req)))
			return -1;

		session->sequence_number_req = 0;
		SPDM_DBG_HEXDUMP(session->encryption_key_req,
			sizeof(session->encryption_key_req), "Key (req)");
		SPDM_DBG_HEXDUMP(session->encryption_salt_req,
			sizeof(session->encryption_salt_req), "Salt (req)");
	} else {
		SPDM_DBG_HEXDUMP(session->session_secret_rsp, 48, "Old secret (rsp)");
		mbedtls_hkdf_expand(md_info, session->session_secret_rsp, 48, bin_str, bin_size,
				new_session_secret, sizeof(new_session_secret));
		SPDM_DBG_HEXDUMP(new_session_secret, sizeof(new_session_secret), "New secret (rsp)");
		memcpy(session->session_secret_rsp, new_session_secret, sizeof(new_session_secret));
		if (spdm_gen_key_iv(context, new_session_secret,
				session->encryption_key_rsp, sizeof(session->encryption_key_rsp),
				session->encryption_salt_rsp, sizeof(session->encryption_salt_rsp)))
			return -1;

		session->sequence_number_rsp = 0;
		SPDM_DBG_HEXDUMP(session->encryption_key_rsp,
			sizeof(session->encryption_key_rsp), "Key (rsp)");
		SPDM_DBG_HEXDUMP(session->encryption_salt_rsp,
			sizeof(session->encryption_salt_rsp), "Salt (rsp)");
	}

	return 0;
}

int spdm_prepare_handshake_data(struct spdm_context *context, struct spdm_session_context *session, uint8_t *hash, const mbedtls_md_info_t *md_info, bool is_psk)
{
	uint8_t bin_str[96];
	uint8_t salt_0[48];
	size_t bin_size = sizeof(bin_str);
	uint8_t *master_secret = NULL;
	uint8_t *handshake_secret = NULL;

	/*
	 * Handshake secret will be used in later stages like
	 * generate handshake master secret and session master secret
	 * to keep the handshake secret data
	 */
	handshake_secret = malloc(48);
	if (handshake_secret) {
		memset(salt_0, 0, sizeof(salt_0));

		if (is_psk) {
			uint8_t psk_data[48], psk_data_len = sizeof(psk_data);

			if (gen_psk_data(session, psk_data, &psk_data_len)) {
				LOG_ERR("Generate psk data failed");
				return -1;
			}
			SPDM_DBG_HEXDUMP(psk_data, psk_data_len, "Shared secret");
			mbedtls_md_hmac(md_info, salt_0, sizeof(salt_0), psk_data,
					psk_data_len, handshake_secret);
			// to clean PSK data
			memset(psk_data, 0, psk_data_len);
		} else {
			SPDM_DBG_HEXDUMP(session->shared_secret,
					session->secret_len, "Shared secret");
			mbedtls_md_hmac(md_info, salt_0, sizeof(salt_0), session->shared_secret,
					session->secret_len, handshake_secret);
		}
		SPDM_DBG_HEXDUMP(handshake_secret, 48, "Handshake_secret");
		session->handshake_secret = handshake_secret;
	} else {
		LOG_ERR("Failed to allocate memory for handshake_secret");
		return -1;
	}

	/*
	 * Request/response master secret will be used in later stages.
	 * For example : generate handshake key/vector and finish key.
	 * To keep the master secret data for later stage.
	 */
	master_secret = malloc(48);
	if (master_secret) {
		memset(master_secret, 0, 48);
		/* Request direction Handshake Secret =
		 *     HKDF-Expand(handshake_secret, bin_str1, hash.length)
		 * bin_str1 = BinConcat(Hash.length, Version, "req hs data", TH1)
		 */
		spdm_bin_concat(context, SPDM_BIN_LABEL_STR_1, strlen(SPDM_BIN_LABEL_STR_1), hash,
				48, bin_str, &bin_size, SPDM_LABEL_MSG_LEN_1);
		SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR1");
		mbedtls_hkdf_expand(md_info, session->handshake_secret, 48, bin_str, bin_size,
				master_secret, 48);
		SPDM_DBG_HEXDUMP(master_secret, 48, "Master secret (req)");
		session->master_secret_req = master_secret;
	} else {
		LOG_ERR("Failed to allocate memory for master_secret_req");
		return -1;
	}

	master_secret = malloc(48);
	if (master_secret) {
		memset(master_secret, 0, 48);
		memset(bin_str, 0, sizeof(bin_str));
		bin_size = sizeof(bin_str);
		/* Response direction Handshake Secret =
		 *     HKDF-Expand(handshake_secret, bin_str2, hash.length)
		 * bin_str2 = BinConcat(Hash.length, Version, "rsp hs data", TH1)
		 */
		spdm_bin_concat(context, SPDM_BIN_LABEL_STR_2, strlen(SPDM_BIN_LABEL_STR_2), hash,
				48, bin_str, &bin_size, SPDM_LABEL_MSG_LEN_2);
		SPDM_DBG_HEXDUMP(bin_str, bin_size, "BIN_STR2");
		mbedtls_hkdf_expand(md_info, session->handshake_secret, 48, bin_str, bin_size,
				master_secret, 48);
		SPDM_DBG_HEXDUMP(master_secret, 48, "Master secret (rsp)");
		session->master_secret_rsp = master_secret;
	} else {
		LOG_ERR("Failed to allocate memory for master_secret_rsp");
		return -1;
	}

	if (spdm_gen_handshake_key_iv(context, session, SPDM_RESPONSE_MODE))
		return -1;

	if (spdm_gen_handshake_key_iv(context, session, SPDM_REQUEST_MODE))
		return -1;

	return 0;
}

int spdm_prepare_hmac_data(struct spdm_context *context, struct spdm_session_context *session, uint8_t key_id, struct spdm_message *req_msg, struct spdm_message *rsp_msg, const mbedtls_md_info_t *md_info, bool is_psk)
{
	int ret;
	uint8_t finish_key[48];

	if (spdm_gen_finish_key(context, session, SPDM_RESPONSE_MODE, finish_key))
		return -1;

	// Prepare hmac data for finish body validation
	// 1. VCA (Note: context->message_a)
	// 2. Hash(CertChain_SlotID DER) if key_exchange is used
	// 3. [KEY_EXCHANGE].*
	// 4. [KEY_EXCHANGE_RSP].*

	mbedtls_md_context_t *hmac_tmp = malloc(sizeof(mbedtls_md_context_t));

	LOG_INF("PSK = %d", is_psk);
	/* Prepare data for responser side */
	if (hmac_tmp) {
		mbedtls_md_init(hmac_tmp);
		ret = mbedtls_md_setup(hmac_tmp, md_info, 1);
		ret = mbedtls_md_hmac_starts(hmac_tmp, finish_key, 48);
		SPDM_DBG_HEXDUMP(context->message_a.data, context->message_a.write_ptr, "VCA");
		ret = mbedtls_md_hmac_update(hmac_tmp, context->message_a.data,
					context->message_a.write_ptr);

		if (is_psk == false) {
			if (session->session_type == SPDM_RESPONSE_MODE) {
				SPDM_DBG_HEXDUMP(context->local.certificate.certs[key_id].digest,
					48, "HASH CERT");
				ret = mbedtls_md_hmac_update(hmac_tmp,
					context->local.certificate.certs[key_id].digest, 48);
			} else {
				SPDM_DBG_HEXDUMP(context->remote.certificate.certs[key_id].digest,
					48, "HASH CERT");
				ret = mbedtls_md_hmac_update(hmac_tmp,
					context->remote.certificate.certs[key_id].digest, 48);
			}
		}
		SPDM_DBG_HEXDUMP(&req_msg->header, 4, "PSK_EX/KEY_EX REQ HEAD");
		ret = mbedtls_md_hmac_update(hmac_tmp, (uint8_t *)&req_msg->header, 4);

		LOG_INF("PSK_EX/KEY_EX REQ MSG data length = %d", req_msg->buffer.write_ptr);
		SPDM_DBG_HEXDUMP(req_msg->buffer.data, req_msg->buffer.write_ptr,
				"PSK_EX/KEY_EX REQ MSG");
		ret = mbedtls_md_hmac_update(hmac_tmp, req_msg->buffer.data,
					req_msg->buffer.write_ptr);

		LOG_HEXDUMP_INF(&rsp_msg->header, 4, "PSK_EX/KEY_EX RSP HEAD");
		ret = mbedtls_md_hmac_update(hmac_tmp, (uint8_t *)&rsp_msg->header, 4);

		LOG_INF("PSK_EX/KEY_EX RSP MSG data length = %d", rsp_msg->buffer.write_ptr);
		SPDM_DBG_HEXDUMP(rsp_msg->buffer.data, rsp_msg->buffer.write_ptr,
				"PSK_EX/KEY_EX RSP MSG");
		ret = mbedtls_md_hmac_update(hmac_tmp, rsp_msg->buffer.data,
					rsp_msg->buffer.write_ptr);
		session->rsp_hmac = hmac_tmp;
	} else {
		LOG_ERR("Failed to allocate memory for rsp_hmac");
		return -1;
	}

	memset(finish_key, 0, sizeof(finish_key));
	if (spdm_gen_finish_key(context, session, SPDM_REQUEST_MODE, finish_key))
		return -1;
	hmac_tmp = malloc(sizeof(mbedtls_md_context_t));

	/* Prepare data for requester side */
	if (hmac_tmp) {
		mbedtls_md_init(hmac_tmp);
		ret = mbedtls_md_setup(hmac_tmp, md_info, 1);
		ret = mbedtls_md_hmac_starts(hmac_tmp, finish_key, 48);
		ret = mbedtls_md_hmac_update(hmac_tmp, context->message_a.data,
					context->message_a.write_ptr);
		if (is_psk == false) {
			if (session->session_type == SPDM_RESPONSE_MODE) {
				SPDM_DBG_HEXDUMP(context->local.certificate.certs[key_id].digest,
					48, "HASH CERT");
				ret = mbedtls_md_hmac_update(hmac_tmp,
					context->local.certificate.certs[key_id].digest, 48);
			} else {
				SPDM_DBG_HEXDUMP(context->remote.certificate.certs[key_id].digest,
					48, "HASH CERT");
				ret = mbedtls_md_hmac_update(hmac_tmp,
					context->remote.certificate.certs[key_id].digest, 48);
			}
		}
		ret = mbedtls_md_hmac_update(hmac_tmp, (uint8_t *)&req_msg->header, 4);
		ret = mbedtls_md_hmac_update(hmac_tmp, req_msg->buffer.data,
					req_msg->buffer.write_ptr);
		ret = mbedtls_md_hmac_update(hmac_tmp, (uint8_t *)&rsp_msg->header, 4);
		ret = mbedtls_md_hmac_update(hmac_tmp, rsp_msg->buffer.data,
					rsp_msg->buffer.write_ptr);
		session->req_hmac = hmac_tmp;
	} else {
		LOG_ERR("Failed to allocate memory for req_hmac");
		return -1;
	}

	return 0;
}

int spdm_compute_shared_data(struct spdm_context *context, struct spdm_session_context *session,
				uint8_t *dhe, mbedtls_ecdh_context *ecdh_ctx)
{
	uint8_t *pkey = NULL;
	int ret = -1;

	/* Calculate Shared Secret */
	ret = mbedtls_mpi_lset(&ecdh_ctx->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(Z), 1);
	if (ret != 0) {
		LOG_ERR("mbedtls_mpi_lset ret=%d", ret);
		goto exit_ecdh;
	}

	ret = mbedtls_mpi_read_binary(&ecdh_ctx->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(X),
			dhe, 48);
	if (ret != 0) {
		LOG_ERR("mbedtls_mpi_read_binary X ret=%d", ret);
		goto exit_ecdh;
	}

	ret = mbedtls_mpi_read_binary(&ecdh_ctx->MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(Y),
			dhe + 48, 48);
	if (ret != 0) {
		LOG_ERR("mbedtls_mpi_read_binary Y ret=%d", ret);
		goto exit_ecdh;
	}

	ret = mbedtls_ecdh_compute_shared(&ecdh_ctx->MBEDTLS_PRIVATE(grp),
			&ecdh_ctx->MBEDTLS_PRIVATE(z), &ecdh_ctx->MBEDTLS_PRIVATE(Qp),
			&ecdh_ctx->MBEDTLS_PRIVATE(d), context->random_callback, NULL);
	if (ret != 0) {
		LOG_ERR("mbedtls_ecdh_compute_shared ret=%d", ret);
		goto exit_ecdh;
	}

	/* Common Secret Key! */
	pkey = malloc(96);
	if (pkey == NULL) {
		LOG_ERR("Failed to allocate memory for key");
		goto exit_ecdh;
	}
	memset(pkey, 0, 96);
	ret = mbedtls_mpi_write_binary(&ecdh_ctx->MBEDTLS_PRIVATE(z), pkey, 48);
	if (ret != 0) {
		LOG_ERR("mbedtls_mpi_write_binary ret=%d", ret);
		goto exit_ecdh;
	}
	SPDM_DBG_HEXDUMP(pkey, 48, "SECRET KEY");

	// DHE Secret
	memcpy(session->shared_secret, pkey, 48);
	session->secret_len = 48;
	if (pkey)
		free(pkey);

	return 0;

exit_ecdh:
	mbedtls_ecdh_free(ecdh_ctx);

	if (pkey)
		free(pkey);
	return ret;
}
