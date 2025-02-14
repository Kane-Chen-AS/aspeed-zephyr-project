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
#include <stdlib.h>

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

static int validate_finish_body(struct spdm_context *context, struct spdm_session_context *session, struct spdm_message *req_msg)
{
	int ret;
	uint8_t hash[SPDM_MAX_HASH_SIZE] = {0};
	mbedtls_md_context_t *md_ctx = session->req_hmac;
	uint8_t sig_offset = 0;
	uint8_t key_id = req_msg->header.param2;

	LOG_INF("Validate finish for session [%x]", session->session_id);
	/* Verify the signature part if the parameter 1 is set */
	if (req_msg->header.param1) {
		mbedtls_sha512_context th1;

		mbedtls_sha512_init(&th1);
		mbedtls_sha512_starts(&th1, 1);
		mbedtls_sha512_clone(&th1, &context->th2_context);

		mbedtls_sha512_update(&th1, context->remote.certificate.certs[key_id].digest,
			sizeof(context->remote.certificate.certs[key_id].digest));
		mbedtls_sha512_update(&th1, (uint8_t *)&req_msg->header, sizeof(req_msg->header));
		mbedtls_sha512_finish(&th1, hash);
		mbedtls_sha512_free(&th1);
		SPDM_DBG_HEXDUMP(hash, 48, "T HASH");

		ret = spdm_crypto_verify(context, 0,
				hash, 48,
				(uint8_t *)req_msg->buffer.data, 96,
				req_msg->header.spdm_version == SPDM_VERSION_12,
				SPDM_SIGN_CONTEXT_FINISH_REQ, strlen(SPDM_SIGN_CONTEXT_FINISH_REQ));

		if (ret) {
			LOG_ERR("Finish req sign verification is failed, ret = %x", -ret);
			return -1;
		}
		sig_offset = 96;
	}

	/* Verify hmac part */
	if (spdm_isCapabilitiesEnabled(context, SPDM_MUT_AUTH_CAP)) {
		SPDM_DBG_HEXDUMP(context->remote.certificate.certs[key_id].digest,
				48, "Remote Cert digest :");
		mbedtls_md_hmac_update(md_ctx, context->remote.certificate.certs[key_id].digest, 48);
		mbedtls_md_hmac_update(md_ctx, (uint8_t *)&req_msg->header, sizeof(req_msg->header));
		mbedtls_md_hmac_update(md_ctx, req_msg->buffer.data, 96);
	} else {
		mbedtls_md_hmac_update(md_ctx, (uint8_t *)&req_msg->header, sizeof(req_msg->header));
	}
	ret = mbedtls_md_hmac_finish(md_ctx, hash);
	/* After this stage, request hmac is not needed anymore, to release for saving memory */
	mbedtls_md_free(md_ctx);
	free(md_ctx);
	session->req_hmac = NULL;
	if (memcmp(hash, (uint8_t *)req_msg->buffer.data + sig_offset, 48)) {
		LOG_ERR("Hmac validation is failed");
		LOG_HEXDUMP_INF(hash, sizeof(hash), "Calculated hmac :");
		return -1;
	}

	return 0;
}

int spdm_handle_finish(void *ctx, void *req, void *rsp, uint32_t *session_id)
{
	LOG_DBG("Enter FINISH");
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	int ret = -1;
	uint8_t key_id;
	uint8_t hmac[MBEDTLS_MD_MAX_SIZE] = {0};
	mbedtls_md_context_t *md_ctx;
	struct spdm_session_context *session;

	LOG_HEXDUMP_INF(&req_msg->header, 4, "FINISH Header");
	SPDM_DBG_HEXDUMP(req_msg->buffer.data, req_msg->buffer.write_ptr, "FINISH");

	/* Verify Request Message */
	if (req_msg->header.spdm_version != SPDM_VERSION_11 &&
			req_msg->header.spdm_version != SPDM_VERSION_12) {
		LOG_ERR("Unsupported version %02x", req_msg->header.spdm_version);
		goto cleanup;
	} else if (req_msg->header.param1 != 0 && req_msg->header.param2 != 0) {
		LOG_ERR("MutAuthUnsupported param1=%02x param2=%02x",
				req_msg->header.param1, req_msg->header.param2);
		goto cleanup;
	} else if (req_msg->buffer.write_ptr < 48) {
		/* When Mutual Authentication is used, the request body will be bigger than 48 */
		LOG_ERR("Message length incorrect %d", req_msg->buffer.write_ptr);
		goto cleanup;
	} else if (req_msg->header.param2 > 7) {
		LOG_ERR("Incorrect SlotID %02x", req_msg->header.param2);
		goto cleanup;
	}
	key_id = req_msg->header.param2;

	if (session_id == NULL)
		session = find_pending_session();
	else
		session = spdm_session_get(*session_id);

	if (session == NULL) {
		LOG_ERR("Failed to find session context (%x)", *session_id);
		goto cleanup;
	}

	if (validate_finish_body(context, session, req_msg)) {
		LOG_ERR("Finish body validation is failed");
		goto cleanup;
	}

	/* Generate Response Message */
	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_FINISH_RSP;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	md_ctx = session->rsp_hmac;
	if (spdm_isCapabilitiesEnabled(context, SPDM_MUT_AUTH_CAP))
		mbedtls_md_hmac_update(md_ctx, context->remote.certificate.certs[key_id].digest, 48);

	ret = mbedtls_md_hmac_update(md_ctx, (uint8_t *)&req_msg->header, 4);
	ret = mbedtls_md_hmac_update(md_ctx, req_msg->buffer.data, req_msg->buffer.write_ptr);
	ret = mbedtls_md_hmac_update(md_ctx, (uint8_t *)&rsp_msg->header, 4);
	ret = mbedtls_md_hmac_finish(md_ctx, hmac);

	SPDM_DBG_HEXDUMP(hmac, sizeof(hmac), "TH2 hmac:");
	/* After this stage, respond hmac is not needed anymore, to release for saving memory */
	mbedtls_md_free(md_ctx);
	free(md_ctx);
	session->rsp_hmac = NULL;

	/* ResponderVerifyData (H)
	 * If the Session Handshake Phase is encrypted and/or message authenticated
	 * (that is, if either the Requester or the Responder set HANDSHAKE_IN_THE_CLEAR_CAP
	 * to 0), this field shall be absent.
	 */
	spdm_buffer_init(&rsp_msg->buffer, 48);
	spdm_buffer_append_array(&rsp_msg->buffer, hmac, 48);

	if (spdm_isCapabilitiesEnabled(context, SPDM_MUT_AUTH_CAP))
		mbedtls_sha512_update(&context->th2_context,
			context->remote.certificate.certs[key_id].digest, 48);
	mbedtls_sha512_update(&context->th2_context, (uint8_t *)&req_msg->header,
			sizeof(req_msg->header));
	mbedtls_sha512_update(&context->th2_context, req_msg->buffer.data,
			req_msg->buffer.write_ptr);
	mbedtls_sha512_update(&context->th2_context, (uint8_t *)&rsp_msg->header,
			sizeof(rsp_msg->header));
	mbedtls_sha512_update(&context->th2_context, rsp_msg->buffer.data,
			rsp_msg->buffer.write_ptr);

	LOG_HEXDUMP_INF(&rsp_msg->header, 4, "FINISH_RSP Header");
	SPDM_DBG_HEXDUMP(rsp_msg->buffer.data, rsp_msg->buffer.write_ptr, "FINISH_RSP");

	/* Calculate Hash for generating session key */
	mbedtls_sha512_finish(&context->th2_context, hmac);
	SPDM_DBG_HEXDUMP(hmac, sizeof(hmac), "TH2 hash :");

	ret = spdm_gen_session_key_iv(context, session, SPDM_RESPONSE_MODE, hmac, false);
	if (ret) {
		LOG_ERR("Failed to generate session key for rep side");
		goto cleanup;
	}
	ret = spdm_gen_session_key_iv(context, session, SPDM_REQUEST_MODE, hmac, false);
	if (ret) {
		LOG_ERR("Failed to generate session key for rsp side");
		goto cleanup;
	}
	session->connection_state = SPDM_STATE_SESSION_ESTABLISHED;

cleanup:
	return ret;
}
