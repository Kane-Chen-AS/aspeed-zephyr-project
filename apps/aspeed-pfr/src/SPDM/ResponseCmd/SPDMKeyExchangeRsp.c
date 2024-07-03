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
#include <mbedtls/md.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <stdlib.h>

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

static int gen_exchange_data(struct spdm_context *context, struct spdm_session_context *session, uint8_t *req_dhe, uint8_t *rsp_dhe)
{
	int ret = -1;
	mbedtls_ecdh_context ecdh_ctx;

	mbedtls_ecdh_init(&ecdh_ctx);
	/* Generate Client Public Key */
	ret = mbedtls_ecp_group_load(&ecdh_ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP384R1);
	if (ret != 0) {
		LOG_ERR("Unsupported Algorithm MBEDTLS_ECP_DP_SECP384R1 ret=%x", -ret);
		goto exit_ecdh;
	}

	ret = mbedtls_ecdh_gen_public(&ecdh_ctx.MBEDTLS_PRIVATE(grp),
			&ecdh_ctx.MBEDTLS_PRIVATE(d),
			&ecdh_ctx.MBEDTLS_PRIVATE(Q),
			context->random_callback,
			NULL);
	if (ret != 0) {
		LOG_ERR("Failed to generate public key ret=%x", -ret);
		goto exit_ecdh;
	}

	ret = mbedtls_mpi_write_binary(&ecdh_ctx.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X),
			rsp_dhe, 48);
	if (ret != 0) {
		LOG_ERR("mbedtls_mpi_write_binary X ret=%d", -ret);
		goto exit_ecdh;
	}
	ret = mbedtls_mpi_write_binary(&ecdh_ctx.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y),
			rsp_dhe + 48, 48);
	if (ret != 0) {
		LOG_ERR("mbedtls_mpi_write_binary Y ret=%d", -ret);
		goto exit_ecdh;
	}
	LOG_HEXDUMP_DBG(rsp_dhe, 96, "RSP DHE");

	if (spdm_compute_shared_data(context, session, req_dhe, &ecdh_ctx)) {
		LOG_ERR("Compute shared data is failed");
		ret = -1;
		goto exit_ecdh;
	}
exit_ecdh:

	mbedtls_ecdh_free(&ecdh_ctx);

	return ret;
}

int spdm_handle_key_exchange(void *ctx, void *req, void *rsp)
{
	LOG_DBG("Enter KEY_EXCHANGE");
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret = -1;
	uint8_t slot_id, key_id;
	/* TODO: Verify Request Message */
	uint8_t *req_dhe = malloc(96);
	size_t req_dhe_size = 96;
	uint16_t req_id = 0;
	uint8_t session_policy = 0;

	LOG_HEXDUMP_INF(&req_msg->header, 4, "KEY_EXCHANGE Header");
	// Request body has secret info, don't display it in regular mode
	LOG_INF("KEY_EXCHANGE, data length = %d", req_msg->buffer.write_ptr);
	SPDM_DBG_HEXDUMP(req_msg->buffer.data, req_msg->buffer.write_ptr, "KEY_EXCHANGE");

	if (req_msg->header.spdm_version != SPDM_VERSION_11 &&
		req_msg->header.spdm_version != SPDM_VERSION_12) {
		LOG_ERR("Unsupported version Req %02x", req_msg->header.spdm_version);
		goto cleanup;
	} else if (req_msg->header.param1 != 0 && req_msg->header.param1 != 1 &&
		req_msg->header.param1 != 0xFF) {
		LOG_ERR("Incorrect type of measurement summary hash %02x", req_msg->header.param1);
		goto cleanup;
	} else if (req_msg->header.param2 > 7) {
		LOG_ERR("Incorrect SlotID %02x", req_msg->header.param2);
		goto cleanup;
	}
	key_id = req_msg->header.param2;

	if (req_dhe == NULL) {
		LOG_ERR("Failed to allocate memory for req_dhe");
		goto cleanup;
	}

	spdm_buffer_get_u16(&req_msg->buffer, &req_id);
	spdm_buffer_get_u8(&req_msg->buffer, &session_policy);
	spdm_buffer_get_reserved(&req_msg->buffer, 1);
	spdm_buffer_get_reserved(&req_msg->buffer, 32); // Nonce
	spdm_buffer_get_array(&req_msg->buffer, req_dhe, req_dhe_size);

	/* Generate Response Message */

	/* Create Session Info */
	slot_id = get_free_session_slot();
	if (slot_id == SPDM_NO_EMPTY_SESSION_CODE) {
		LOG_ERR("No empty session context");
		return SPDM_NO_EMPTY_SESSION_CODE;
	}

	struct spdm_session_context *session;

	session = spdm_session_create(slot_id, req_id,
			slot_id + SPDM_SESSION_ID_BASE, SPDM_HEARTBEAT_PERIOD);
	session->session_type = SPDM_RESPONSE_MODE;
	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_KEY_EXCHANGE_RSP;
	// HEARTBEAT Period in Second
	rsp_msg->header.param1 = SPDM_HEARTBEAT_PERIOD;
	rsp_msg->header.param2 = 0;

	spdm_buffer_init(&rsp_msg->buffer, 512);
	spdm_buffer_append_u16(&rsp_msg->buffer, slot_id + SPDM_SESSION_ID_BASE);
	context->local.session_id = slot_id + SPDM_SESSION_ID_BASE;
	context->remote.session_id = req_id;

	// MutAuthRequested
	if (spdm_isCapabilitiesEnabled(context, SPDM_MUT_AUTH_CAP))
		spdm_buffer_append_u8(&rsp_msg->buffer, SPDM_MUT_AUTH_MODE);
	else
		spdm_buffer_append_u8(&rsp_msg->buffer, 0);

	// SlotParam
	spdm_buffer_append_u8(&rsp_msg->buffer, 0x00);

	// Random data
	spdm_buffer_append_nonce(&rsp_msg->buffer);

	// Generate Exchange Data (D)
	uint8_t *rsp_dhe = malloc(96);

	if (rsp_dhe)
		gen_exchange_data(context, session, req_dhe, rsp_dhe);
	else {
		LOG_ERR("Failed to allocate memory for rsp_dhe");
		goto cleanup;
	}
	spdm_buffer_append_array(&rsp_msg->buffer, rsp_dhe, 96);
	free(rsp_dhe);

	// TODO: Measurement Hash (H)
	uint8_t *hash = malloc(64), *sig = malloc(128);

	if (hash == NULL) {
		LOG_ERR("Failed to allocate memory for hash");
		goto cleanup2;
	}
	if (sig == NULL) {
		LOG_ERR("Failed to allocate memory for sig");
		goto cleanup2;
	}

	if (req_msg->header.param1 != 0)
		spdm_buffer_append_array(&rsp_msg->buffer, hash, 48);

	// Add Opaque data
	spdm_buffer_append_u16(&rsp_msg->buffer, 0x0c);
	spdm_buffer_append_u8(&rsp_msg->buffer, 0x01); /* Total Element */
	spdm_buffer_append_reserved(&rsp_msg->buffer, 3);
	spdm_buffer_append_u8(&rsp_msg->buffer, 0x00); /* ID */
	spdm_buffer_append_u8(&rsp_msg->buffer, 0x00); /* Vendor ID Length */
	spdm_buffer_append_u16(&rsp_msg->buffer, 0x04); /* OpaqueElementDataLen */
	spdm_buffer_append_u8(&rsp_msg->buffer, 0x01);
	spdm_buffer_append_u8(&rsp_msg->buffer, 0x00);
	spdm_buffer_append_u8(&rsp_msg->buffer, 0x00);
	spdm_buffer_append_u8(&rsp_msg->buffer, 0x10);

	// Signature
	// SPDMsign(PrivKey, transcript, "key_exchange_rsp signing")
	// 1. VCA (Note: context->message_a)
	// 2. Hash(CertChain_SlotID DER)
	// 3. [KEY_EXCHANGE].*
	// 4. [KEY_EXCHANGE_RSP].* except the signature and ResponderVerifyData

	mbedtls_sha512_context th1;

	mbedtls_sha512_init(&th1);
	mbedtls_sha512_starts(&th1, 1);

	mbedtls_sha512_update(&th1, context->message_a.data, context->message_a.write_ptr);
	mbedtls_sha512_update(&th1, context->local.certificate.certs[key_id].digest, 48);
	mbedtls_sha512_update(&th1, (uint8_t *)&req_msg->header, 4);
	mbedtls_sha512_update(&th1, req_msg->buffer.data, req_msg->buffer.write_ptr);
	mbedtls_sha512_update(&th1, (uint8_t *)&rsp_msg->header, 4);
	mbedtls_sha512_update(&th1, rsp_msg->buffer.data, rsp_msg->buffer.write_ptr);

	// Continue for TH2 generation
	mbedtls_sha512_free(&context->th2_context);
	mbedtls_sha512_init(&context->th2_context);
	mbedtls_sha512_clone(&context->th2_context, &th1);

	size_t sig_size = 0;

	mbedtls_sha512_finish(&th1, hash);
	// Sign the hash
	SPDM_DBG_HEXDUMP(hash, 48, "T HASH");
	spdm_crypto_sign(context, hash, 48, sig, &sig_size, true,
			SPDM_SIGN_CONTEXT_KEY_EXCHANGE_RSP,
			strlen(SPDM_SIGN_CONTEXT_KEY_EXCHANGE_RSP), SPDM_RESPONSE_MODE);

	spdm_buffer_append_array(&rsp_msg->buffer, sig, sig_size);
	mbedtls_sha512_update(&context->th2_context, sig, sig_size);
	/* Duplicate th2_context because th2_context will be used in later stage */
	mbedtls_sha512_clone(&th1, &context->th2_context);
	mbedtls_sha512_finish(&th1, hash);
	SPDM_DBG_HEXDUMP(hash, 48, "TH1 HASH");
	SPDM_DBG_HEXDUMP(sig, sig_size, "SIGNATURE");

	// TODO: ResponderVerifyData (H) if (HANDSHAKE_IN_THE_CLEAR_CAP == 0)
	// HMAC
	// spdm_buffer_append_array(&rsp_msg->buffer, );

	LOG_HEXDUMP_INF(&rsp_msg->header, 4, "KEY_EXCHANGE_RSP Header");
	SPDM_DBG_HEXDUMP(rsp_msg->buffer.data, rsp_msg->buffer.write_ptr, "KEY_EXCHANGE_RSP");

	const mbedtls_md_info_t *md_info;

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
	if (spdm_prepare_handshake_data(context, session, hash, md_info, false)) {
		LOG_ERR("Failed to generate PSK handshake data");
		goto cleanup3;
	}
	if (spdm_prepare_hmac_data(context, session, key_id, req_msg, rsp_msg, md_info, false)) {
		LOG_ERR("Failed to generate hmac data");
		goto cleanup3;
	}
	ret = 0;
	session->connection_state = SPDM_STATE_KEY_EXCHANGED;

cleanup3:
	mbedtls_sha512_free(&th1);

cleanup2:
	if (sig)
		free(sig);
	if (hash)
		free(hash);
cleanup:
	if (req_dhe)
		free(req_dhe);
	LOG_DBG("Leave KEY_EXCHANGE");
	return ret;
}
