/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMKeyOperation.h"

#include <mbedtls/sha512.h>
#include <mbedtls/md.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

static int gen_key_exchange_data(struct spdm_context *context, struct spdm_session_context *session, uint8_t *req_dhe, mbedtls_ecdh_context *ecdh_ctx)
{
	int ret = -1;

	mbedtls_ecdh_init(ecdh_ctx);

	/* Generate Client Public Key */
	ret = mbedtls_ecp_group_load(&ecdh_ctx->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP384R1);
	if (ret != 0) {
		LOG_ERR("Unsupported Algorithm MBEDTLS_ECP_DP_SECP384R1 ret=%x", -ret);
		goto exit_ecdh;
	}

	ret = mbedtls_ecdh_gen_public(&ecdh_ctx->MBEDTLS_PRIVATE(grp),
			&ecdh_ctx->MBEDTLS_PRIVATE(d),
			&ecdh_ctx->MBEDTLS_PRIVATE(Q),
			context->random_callback,
			NULL);
	if (ret != 0) {
		LOG_ERR("Failed to generate public key ret=%x", -ret);
		goto exit_ecdh;
	}

	ret = mbedtls_mpi_write_binary(&ecdh_ctx->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X),
			req_dhe, 48);
	if (ret != 0) {
		LOG_ERR("mbedtls_mpi_write_binary X ret=%d", -ret);
		goto exit_ecdh;
	}
	ret = mbedtls_mpi_write_binary(&ecdh_ctx->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y),
			req_dhe + 48, 48);
	if (ret != 0) {
		LOG_ERR("mbedtls_mpi_write_binary Y ret=%d", -ret);
		goto exit_ecdh;
	}
	SPDM_DBG_HEXDUMP(req_dhe, 96, "Req DHE");

	return 0;

exit_ecdh:
	mbedtls_ecdh_free(ecdh_ctx);
	return ret;
}

static int verify_sig(struct spdm_context *context, struct spdm_message *req_msg, struct spdm_message *rsp_msg, uint8_t *sig, uint16_t req_len)
{
	int result = -1;
	uint8_t *hash = NULL;
	mbedtls_sha512_context th1;

	hash = malloc(64);
	if (hash == NULL) {
		LOG_ERR("Failed to allocate memory for hash (64)");
		return result;
	}

	mbedtls_sha512_init(&th1);
	mbedtls_sha512_starts(&th1, 1);

	mbedtls_sha512_update(&th1, context->message_a.data, context->message_a.write_ptr);
	mbedtls_sha512_update(&th1, context->remote.certificate.certs[0].digest, 48);
	mbedtls_sha512_update(&th1, (uint8_t *)&req_msg->header, 4);
	mbedtls_sha512_update(&th1, req_msg->buffer.data, req_msg->buffer.write_ptr);
	mbedtls_sha512_update(&th1, (uint8_t *)&rsp_msg->header, 4);
	mbedtls_sha512_update(&th1, rsp_msg->buffer.data, req_len);

	mbedtls_sha512_free(&context->th2_context);
	mbedtls_sha512_init(&context->th2_context);
	mbedtls_sha512_clone(&context->th2_context, &th1);

	mbedtls_sha512_finish(&th1, hash);
	mbedtls_sha512_free(&th1);
	SPDM_DBG_HEXDUMP(hash, 48, "T HASH");

	result = spdm_crypto_verify(context, 0, hash, 48,
			sig, 96, req_msg->header.spdm_version == SPDM_VERSION_12,
			SPDM_SIGN_CONTEXT_KEY_EXCHANGE_RSP,
			strlen(SPDM_SIGN_CONTEXT_KEY_EXCHANGE_RSP));
	LOG_INF("Sig verify result = %x", -result);

	if (result) {
		LOG_ERR("Signature verification is failed, ret = %x", result);
		free(hash);
		return result;
	}

	mbedtls_sha512_update(&context->th2_context, sig, 96);

	free(hash);
	return 0;
}

int spdm_key_exchange(void *ctx, uint8_t *mutualauth, struct spdm_session_context **session_tmp)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret = -1;
	uint8_t slot_id, session_slot, *OpaqueData = NULL;
	uint8_t *sig = NULL, *hash = NULL, *req_dhe = NULL;
	uint16_t rsp_id = 0, OpaqueDataLength = 0, req_len = 0;
	uint8_t random[32];
	uint8_t buf[96];
	uint8_t meas_sum_hash[48];
	struct spdm_session_context *session = NULL;
	mbedtls_ecdh_context ecdh_ctx;
	mbedtls_sha512_context th1;

	// Fixed to SPDM_10 for GET_VERSION HANDSHAKING
	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_KEY_EXCHANGE;
	/* Type of measurement summary hash requested */
	if (context->remote.capabilities.flags & SPDM_MEAS_CAP_SIG)
		req_msg.header.param1 = 0xff;
	else
		req_msg.header.param1 = 0;
	/* Slot number */
	req_msg.header.param2 = 0;

	spdm_buffer_init(&req_msg.buffer, 150);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	if (req_msg.buffer.data == NULL) {
		LOG_ERR("Failed to allocate memory for key exchange request");
		return -1;
	}

	req_dhe = malloc(96);
	if (req_dhe == NULL) {
		LOG_ERR("Failed to allocate memory for req dhe");
		goto cleanup;
	}

	session_slot = get_free_session_slot();
	if (session_slot == SPDM_NO_EMPTY_SESSION_CODE) {
		LOG_ERR("Session slot is full");
		goto cleanup;
	}

	session = spdm_session_create(session_slot,
			session_slot + SPDM_SESSION_ID_BASE, rsp_id, SPDM_HEARTBEAT_PERIOD);
	session->session_type = SPDM_REQUEST_MODE;
	*session_tmp = session;

	// Req session id
	spdm_buffer_append_u16(&req_msg.buffer, session_slot + SPDM_SESSION_ID_BASE);
	// Session policy
	spdm_buffer_append_u8(&req_msg.buffer, 1);
	spdm_buffer_append_reserved(&req_msg.buffer, 1);
	context->random_callback(context, buf, 32);
	// Requester-provided random data.
	spdm_buffer_append_array(&req_msg.buffer, buf, 32);
	if (gen_key_exchange_data(context, session, req_dhe, &ecdh_ctx)) {
		LOG_ERR("Failed to gen exchange data");
		goto cleanup;
	}
	// DHE public information generated by the Requester.
	spdm_buffer_append_array(&req_msg.buffer, req_dhe, 96);
	// Add Opaque data
	spdm_buffer_append_u16(&req_msg.buffer, 0x10);
	/* Total Element */
	spdm_buffer_append_u8(&req_msg.buffer, 0x01);
	spdm_buffer_append_reserved(&req_msg.buffer, 3);
	/* ID */
	spdm_buffer_append_u8(&req_msg.buffer, 0x00);
	/* Vendor ID Length */
	spdm_buffer_append_u8(&req_msg.buffer, 0x00);
	/* OpaqueElementDataLen */
	spdm_buffer_append_u16(&req_msg.buffer, 0x05);
	spdm_buffer_append_u8(&req_msg.buffer, 0x01);
	spdm_buffer_append_u8(&req_msg.buffer, 0x01);
	spdm_buffer_append_u8(&req_msg.buffer, 0x1);
	spdm_buffer_append_u16(&req_msg.buffer,
			SPDM_VERSION_10 << SPDM_VERSION_NUMBER_ENTRY_SHIFT_BIT);
	spdm_buffer_append_reserved(&req_msg.buffer, 3);

	ret = spdm_send_request(context, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("KEY_EXCHANGE failed %x", ret);
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_KEY_EXCHANGE_RSP) {
		LOG_ERR("Expecting KEY_EXCHANGE_RSP message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		goto cleanup;
	}

	spdm_hexdump_helper((uint8_t *)&rsp_msg.header, 4, "Key Exchange header");
	SPDM_DBG_HEXDUMP(rsp_msg.buffer.data, rsp_msg.buffer.write_ptr, "SPDM rsp");

	session->heartbeatperiod = rsp_msg.header.param1;
	spdm_buffer_get_u16(&rsp_msg.buffer, &rsp_id);
	req_len += 2;
	session->session_id |= rsp_id;
	spdm_buffer_get_u8(&rsp_msg.buffer, mutualauth);
	req_len++;
	spdm_buffer_get_u8(&rsp_msg.buffer, &slot_id);
	req_len++;
	spdm_buffer_get_array(&rsp_msg.buffer, random, 32);
	req_len += 32;
	spdm_buffer_get_array(&rsp_msg.buffer, buf, 96);
	req_len += 96;
	spdm_buffer_get_array(&rsp_msg.buffer, meas_sum_hash, 48);
	req_len += 48;
	spdm_buffer_get_u16(&rsp_msg.buffer, &OpaqueDataLength);
	req_len += 2;
	OpaqueData = malloc(OpaqueDataLength);
	if (OpaqueData == NULL) {
		LOG_ERR("Failed to allocate memory for OpaqueData (%d)", OpaqueDataLength);
		goto cleanup;
	}
	spdm_buffer_get_array(&rsp_msg.buffer, OpaqueData, OpaqueDataLength);
	req_len += OpaqueDataLength;
	sig = malloc(128);
	if (sig == NULL) {
		LOG_ERR("Failed to allocate memory for sig (128)");
		goto cleanup;
	}
	spdm_buffer_get_array(&rsp_msg.buffer, sig, 96);

	if (verify_sig(context, &req_msg, &rsp_msg, sig, req_len)) {
		LOG_ERR("Failed to verify sig");
		goto cleanup;
	}

	if (spdm_compute_shared_data(context, session, buf, &ecdh_ctx)) {
		LOG_ERR("Failed to compute shared data");
		goto cleanup;
	}

	hash = malloc(64);
	if (hash == NULL) {
		LOG_ERR("Failed to allocate memory for hash (64)");
		goto cleanup;
	}
	mbedtls_sha512_init(&th1);
	mbedtls_sha512_starts(&th1, 1);
	mbedtls_sha512_clone(&th1, &context->th2_context);
	mbedtls_sha512_finish(&th1, hash);
	mbedtls_sha512_free(&th1);

	SPDM_DBG_HEXDUMP(hash, 48, "TH1 hash");

	const mbedtls_md_info_t *md_info;

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
	if (spdm_prepare_handshake_data(context, session, hash, md_info, false)) {
		LOG_ERR("Failed to generate PSK handshake data");
		goto cleanup;
	}
	if (spdm_prepare_hmac_data(context, session, 0, &req_msg, &rsp_msg, md_info, false)) {
		LOG_ERR("Failed to generate hmac data");
		goto cleanup;
	}

	session->connection_state = SPDM_STATE_KEY_EXCHANGED;
	ret = 0;

cleanup:
	mbedtls_ecdh_free(&ecdh_ctx);
	spdm_buffer_release(&rsp_msg.buffer);
	spdm_buffer_release(&req_msg.buffer);

	if (ret)
		mbedtls_sha512_free(&context->th2_context);

	if (OpaqueData)
		free(OpaqueData);

	if (sig)
		free(sig);

	if (hash)
		free(hash);

	if (req_dhe)
		free(req_dhe);

	return ret;
}

