/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMSession.h"
#include <mbedtls/ecdh.h>

typedef enum {
	SPDM_KEY_UPDATE_RESERVED,
	SPDM_KEY_UPDATE_SINGLE,
	SPDM_KEY_UPDATE_BOTH,
	SPDM_KEY_UPDATE_VERIFY_KEY,
} SPDM_KEY_UPDATE_OP;

struct spdm_context *find_spdm_context(uint8_t bus, uint8_t src_eid);
int spdm_gen_finish_key(struct spdm_context *context, struct spdm_session_context *session,
		uint8_t mode, uint8_t *out);
int spdm_gen_key_iv(struct spdm_context *context, uint8_t *master_secret, uint8_t *keyout,
		int key_size, uint8_t *ivout, int iv_size);
int spdm_gen_session_key_iv(struct spdm_context *context, struct spdm_session_context *session,
		uint8_t mode, uint8_t *hash_data, bool is_psk);
int spdm_update_key(struct spdm_context *context, struct spdm_session_context *session, uint8_t mode);
int spdm_gen_handshake_key_iv(struct spdm_context *context, struct spdm_session_context *session,
		uint8_t mode);
int spdm_prepare_handshake_data(struct spdm_context *context, struct spdm_session_context *session,
		uint8_t *hash, const mbedtls_md_info_t *md_info, bool is_psk);
int spdm_prepare_hmac_data(struct spdm_context *context, struct spdm_session_context *session,
		uint8_t key_id, struct spdm_message *req_msg, struct spdm_message *rsp_msg,
		const mbedtls_md_info_t *md_info, bool is_psk);
int spdm_compute_shared_data(struct spdm_context *context, struct spdm_session_context *session,
		uint8_t *dhe, mbedtls_ecdh_context *ecdh_ctx);
int spdm_hmac_clone(mbedtls_md_context_t *dst, mbedtls_md_context_t *src);
bool spdm_isCapabilitiesEnabled(struct spdm_context *context, uint32_t flag);
