/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMResponder.h"
#include "SPDM/ResponseCmd/SPDMResponseCmd.h"
#include "SPDM/SPDMSession.h"
#include "SPDM/SPDMKeyOperation.h"

#include <mbedtls/sha512.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <stdlib.h>

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_psk_exchange(void *ctx, void *req, void *rsp)
{
	LOG_INF("Enter PSK EXCHANGE");
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	uint16_t req_id, p_len, r_len, o_len;
	uint8_t hash[SPDM_MAX_HASH_SIZE];
	uint8_t slot_id;
	int ret = -1;

	LOG_HEXDUMP_INF(&req_msg->header, 4, "PSK_EXCHANGE Header");
	// Request body has secret info, don't display it in regular mode
	LOG_INF("PSK_EXCHANGE, data length = %d", req_msg->buffer.write_ptr);
	SPDM_DBG_HEXDUMP(req_msg->buffer.data, req_msg->buffer.write_ptr, "PSK_EXCHANGE");

	/* Retrieve request session id */
	spdm_buffer_get_u16(&req_msg->buffer, &req_id);
	/* Retrieve PSKHint length */
	spdm_buffer_get_u16(&req_msg->buffer, &p_len);
	/* Retrieve RequesterContext length */
	spdm_buffer_get_u16(&req_msg->buffer, &r_len);
	/* Retrieve OpaqueData length */
	spdm_buffer_get_u16(&req_msg->buffer, &o_len);

	LOG_INF("PSKHint length = %d", p_len);
	LOG_INF("RequesterContext length = %d", r_len);
	LOG_INF("OpaqueData length = %d", o_len);

	uint8_t *PSKHint = NULL;
	uint8_t *RequesterContext = NULL;
	uint8_t *OpaqueData = NULL;

	PSKHint = malloc(p_len);
	if (PSKHint == NULL) {
		LOG_ERR("Failed to allocate memory for PSKHint (%d)", p_len);
		goto done;
	}

	RequesterContext = malloc(r_len);
	if (RequesterContext == NULL) {
		LOG_ERR("Failed to allocate memory for RequesterContext (%d)", r_len);
		goto done;
	}

	OpaqueData = malloc(o_len);
	if (OpaqueData == NULL) {
		LOG_ERR("Failed to allocate memory for OpaqueData (%d)", o_len);
		goto done;
	}

	/* Retrieve PSKHint if PSKHint is presented */
	if (p_len)
		spdm_buffer_get_array(&req_msg->buffer, PSKHint, p_len);

	/*
	 * Retrieve RequesterContext
	 * nonce (>= 32 bytes) + optionally relevant information (n bytes)
	 */
	spdm_buffer_get_array(&req_msg->buffer, RequesterContext, r_len);

	/* Retrieve OpaqueData if OpaqueData is presented */
	if (o_len)
		spdm_buffer_get_array(&req_msg->buffer, OpaqueData, o_len);


	slot_id = get_free_session_slot();
	if (slot_id == SPDM_NO_EMPTY_SESSION_CODE) {
		LOG_ERR("No empty session context");
		ret = SPDM_NO_EMPTY_SESSION_CODE;
		goto done;
	}

	struct spdm_session_context *session;

	session = spdm_session_create(slot_id, req_id,
			slot_id + SPDM_SESSION_ID_BASE, SPDM_HEARTBEAT_PERIOD);
	if (p_len <= sizeof(session->shared_secret)) {
		memcpy(session->shared_secret, PSKHint, p_len);
		session->secret_len = p_len;
	}
	context->local.session_id = slot_id + SPDM_SESSION_ID_BASE;
	context->remote.session_id = req_id;

	/* Prepare Response Message */
	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_PSK_EXCHANGE_RSP;
	// HEARTBEAT Period in Second
	rsp_msg->header.param1 = SPDM_HEARTBEAT_PERIOD;
	rsp_msg->header.param2 = 0;

	spdm_buffer_init(&rsp_msg->buffer, 512);
	/* Add respond session id */
	spdm_buffer_append_u16(&rsp_msg->buffer, slot_id + SPDM_SESSION_ID_BASE);
	/* Add reserved data */
	spdm_buffer_append_reserved(&rsp_msg->buffer, 2);
	/* Add Length of ResponderContext */
	spdm_buffer_append_u16(&rsp_msg->buffer, 64);
	// Todo : add OpaqueData
	spdm_buffer_append_u16(&rsp_msg->buffer, 0);

	/* Add Measurement Summary Hash */
	// Todo : this should be generated based on the request parameter, to fill fake data for now
	memset(hash, 0, sizeof(hash));
	spdm_buffer_append_array(&rsp_msg->buffer, hash, 48);

	/* Add ResponderContext */
	// Todo : currently, these data is not used by spdm-emu, to fill fake data for now
	spdm_buffer_append_nonce(&rsp_msg->buffer);
	spdm_buffer_append_nonce(&rsp_msg->buffer);

	/*
	 * Add ResponderVerifyData
	 * calculate TH1
	 * 1. VCA
	 * 2. [PSK_EXCHANGE].*
	 * 3. [PSK_EXCHANGE_RSP].* except the ResponderVerifyData field
	 */
	mbedtls_sha512_context th1;
	const mbedtls_md_info_t *md_info;

	mbedtls_sha512_init(&th1);
	mbedtls_sha512_starts(&th1, 1);

	mbedtls_sha512_update(&th1, context->message_a.data, context->message_a.write_ptr);
	mbedtls_sha512_update(&th1, (uint8_t *)&req_msg->header, 4);
	mbedtls_sha512_update(&th1, req_msg->buffer.data, req_msg->buffer.write_ptr);
	mbedtls_sha512_update(&th1, (uint8_t *)&rsp_msg->header, 4);
	mbedtls_sha512_update(&th1, rsp_msg->buffer.data, rsp_msg->buffer.write_ptr);

	// Continue for TH2 generation
	mbedtls_sha512_free(&context->th2_context);
	mbedtls_sha512_init(&context->th2_context);
	mbedtls_sha512_clone(&context->th2_context, &th1);

	mbedtls_sha512_finish(&th1, hash);
	LOG_HEXDUMP_INF(hash, 48, "T1 HASH");

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);

	if (spdm_prepare_handshake_data(context, session, hash, md_info, true)) {
		LOG_ERR("Failed to generate PSK handshake data");
		goto done;
	}
	if (spdm_prepare_hmac_data(context, session, 0, req_msg, rsp_msg, md_info, true)) {
		LOG_ERR("failed to generate PSK handshake data");
		goto done;
	}
	mbedtls_md_context_t md_ctx;

	mbedtls_md_init(&md_ctx);
	mbedtls_md_setup(&md_ctx, md_info, 1);
	if (spdm_hmac_clone(&md_ctx, session->rsp_hmac)) {
		LOG_ERR("Failed to clone hmac");
		goto done;
	}
	mbedtls_md_hmac_finish(&md_ctx, hash);
	LOG_HEXDUMP_DBG(hash, 48, "HMAC (rsp_hmac)");
	mbedtls_md_free(&md_ctx);

	/* Add ResponderVerifyData data */
	spdm_buffer_append_array(&rsp_msg->buffer, hash, sizeof(hash));

	/* Keep counting the hmac with PSK_EXCHANGE_RSP Header and body */
	mbedtls_md_update(session->rsp_hmac, (uint8_t *)&rsp_msg->header, 4);
	mbedtls_md_update(session->rsp_hmac, rsp_msg->buffer.data, rsp_msg->buffer.write_ptr);

	LOG_HEXDUMP_INF(&rsp_msg->header, 4, "PSK_EXCHANGE_RSP Header");
	SPDM_DBG_HEXDUMP(rsp_msg->buffer.data, rsp_msg->buffer.write_ptr, "PSK_EXCHANGE_RSP");

	/*
	 * We enable SPDM_PSK_CAP this bit so we don't need to enter PSK_FINISH
	 * stage for creating session key
	 */
	mbedtls_sha512_clone(&th1, &context->th2_context);
	mbedtls_sha512_update(&th1, hash, 48);
	mbedtls_sha512_finish(&th1, hash);
	LOG_HEXDUMP_INF(hash, 48, "TH2 hash");

	if (spdm_gen_session_key_iv(context, session, SPDM_RESPONSE_MODE, hash, true)) {
		LOG_ERR("Failed to generate session key for rsp side");
		goto done;
	}
	if (spdm_gen_session_key_iv(context, session, SPDM_REQUEST_MODE, hash, true)) {
		LOG_ERR("Failed to generate session key for req side");
		goto done;
	}

	session->connection_state = SPDM_STATE_SESSION_ESTABLISHED;
	ret = 0;
done:
	if (PSKHint)
		free(PSKHint);

	if (RequesterContext)
		free(RequesterContext);

	if (OpaqueData)
		free(OpaqueData);

	return ret;
}
