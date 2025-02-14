/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMKeyOperation.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int gen_sig_data(struct spdm_context *context, struct spdm_message *req_msg)
{
	int ret;
	mbedtls_sha512_context th1;
	uint8_t hash[SPDM_MAX_HASH_SIZE];
	size_t sig_size;
	uint8_t *sig;

	sig = malloc(128);
	if (sig == NULL) {
		LOG_ERR("Failed to allocate memory for sig (128)");
		return -1;
	}

	mbedtls_sha512_init(&th1);
	mbedtls_sha512_starts(&th1, 1);
	mbedtls_sha512_clone(&th1, &context->th2_context);

	SPDM_DBG_HEXDUMP(context->local.certificate.certs[0].digest, 48, "Cert");
	mbedtls_sha512_update(&th1, context->local.certificate.certs[0].digest,
		sizeof(context->local.certificate.certs[0].digest));
	mbedtls_sha512_update(&th1, (uint8_t *)&req_msg->header, sizeof(req_msg->header));
	mbedtls_sha512_finish(&th1, hash);
	mbedtls_sha512_free(&th1);
	SPDM_DBG_HEXDUMP(hash, 48, "T HASH");

	ret = spdm_crypto_sign(context, hash, 48, sig, &sig_size, true,
			SPDM_SIGN_CONTEXT_FINISH_REQ,
			strlen(SPDM_SIGN_CONTEXT_FINISH_REQ));

	if (ret) {
		LOG_ERR("Finish req sign is failed, ret = %x", -ret);
		free(sig);
		return -1;
	}
	spdm_buffer_append_array(&req_msg->buffer, sig, sig_size);

	free(sig);

	return 0;
}

int gen_verify_data(struct spdm_context *context, struct spdm_session_context *session, struct spdm_message *req_msg, uint8_t mutualauth)
{
	mbedtls_md_context_t *md_ctx;
	uint8_t hash[48];

	md_ctx = session->req_hmac;
	if (md_ctx == NULL) {
		LOG_ERR("%s : md_ctx is NULL", __func__);
		return -1;
	}

	/* Generate hmac part */
	if (mutualauth) {
		SPDM_DBG_HEXDUMP(context->local.certificate.certs[0].digest, 48,
			"Local cert digest :");
		mbedtls_md_hmac_update(md_ctx, context->local.certificate.certs[0].digest, 48);
		mbedtls_md_hmac_update(md_ctx, (uint8_t *)&req_msg->header,
			sizeof(req_msg->header));
		mbedtls_md_hmac_update(md_ctx, req_msg->buffer.data, 96);
	} else
		mbedtls_md_hmac_update(md_ctx, (uint8_t *)&req_msg->header,
			sizeof(req_msg->header));

	mbedtls_md_hmac_finish(md_ctx, hash);
	/* After this stage, hmac for request is not used anymore, to release it for saving memory */
	mbedtls_md_free(md_ctx);
	free(md_ctx);
	session->req_hmac = NULL;
	spdm_buffer_append_array(&req_msg->buffer, hash, sizeof(hash));

	return 0;
}

int verify_finish_rsp(struct spdm_context *context, struct spdm_session_context *session, struct spdm_message *req_msg, struct spdm_message *rsp_msg)
{
	mbedtls_md_context_t *md_ctx;
	int ret;
	uint8_t hmac[48] = {0};

	md_ctx = session->rsp_hmac;
	if (spdm_isCapabilitiesEnabled(context, SPDM_MUT_AUTH_CAP))
		mbedtls_md_hmac_update(md_ctx, context->local.certificate.certs[0].digest, 48);

	ret = mbedtls_md_hmac_update(md_ctx, (uint8_t *)&req_msg->header, 4);
	ret = mbedtls_md_hmac_update(md_ctx, req_msg->buffer.data, req_msg->buffer.write_ptr);
	ret = mbedtls_md_hmac_update(md_ctx, (uint8_t *)&rsp_msg->header, 4);
	ret = mbedtls_md_hmac_finish(md_ctx, hmac);

	if (memcmp(hmac, rsp_msg->buffer.data, rsp_msg->buffer.write_ptr)) {
		LOG_ERR("Validate finish response failed");
		spdm_hexdump_helper(hmac, rsp_msg->buffer.write_ptr, "Received hmac");
		spdm_hexdump_helper(rsp_msg->buffer.data, rsp_msg->buffer.write_ptr,
				"Expected hmac");
		return -1;
	}

	/* After this stage, hmac for request is not used anymore, to release it for saving memory */
	mbedtls_md_free(md_ctx);
	free(md_ctx);
	session->rsp_hmac = NULL;

	return 0;
}

static int copy_remote_cert(struct spdm_context *context, struct spdm_session_context *session)
{
	int ret;
	size_t asn1_len, current_cert_len = 0;
	size_t cert_chain_len = context->remote.certificate.certs[0].size - 4 - 48;
	uint8_t *cert_chain = context->remote.certificate.certs[0].data + 4 + 48;
	uint8_t *tmp_ptr, *current_cert = cert_chain;
	int32_t current_index = -1;

	while (true) {
		tmp_ptr = current_cert;
		ret = mbedtls_asn1_get_tag(
				&tmp_ptr, cert_chain + cert_chain_len, &asn1_len,
				MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		if (ret != 0)
			break;

		current_cert_len = asn1_len + (tmp_ptr - current_cert);
		current_index++;
		current_cert = current_cert + current_cert_len;
	}

	current_cert -= current_cert_len;

	session->cert_data_len = current_cert_len;
	session->cert_data = malloc(current_cert_len);
	if (session->cert_data == NULL) {
		LOG_ERR("Failed to allocate memory for cert data (%d)", current_cert_len);
		return -1;
	}
	memcpy(session->cert_data, current_cert, current_cert_len);

	return 0;
}

int spdm_finish(void *ctx, uint8_t mutualauth, int index)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret = -1;
	struct spdm_session_context *session;
	uint8_t hash[SPDM_MAX_HASH_SIZE];

	session = find_pending_session();
	if (session == NULL) {
		LOG_ERR("Failed to find a pending session");
		return -1;
	}

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_FINISH;
	req_msg.header.param1 = 1; // Signature field is included.
	req_msg.header.param2 = 0; // Slot number

	spdm_buffer_init(&req_msg.buffer, 96 + 48); // Signature + HMAC of the transcript hash
	spdm_buffer_init(&rsp_msg.buffer, 0);

	if (gen_sig_data(context, &req_msg)) {
		LOG_ERR("Generate sig data failed");
		goto cleanup;
	}
	if (gen_verify_data(context, session, &req_msg, mutualauth)) {
		LOG_ERR("Generate verify hmac failed");
		goto cleanup;
	}

	ret = spdm_send_request(context, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("Get FINISH RSP failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_FINISH_RSP) {
		LOG_ERR("Expecting FINISH RSP message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	}

	if (verify_finish_rsp(context, session, &req_msg, &rsp_msg)) {
		ret = -1;
		goto cleanup;
	}

	if (spdm_isCapabilitiesEnabled(context, SPDM_MUT_AUTH_CAP))
		mbedtls_sha512_update(&context->th2_context,
			context->local.certificate.certs[0].digest, 48);
	mbedtls_sha512_update(&context->th2_context, (uint8_t *)&req_msg.header,
			sizeof(req_msg.header));
	mbedtls_sha512_update(&context->th2_context, req_msg.buffer.data,
			req_msg.buffer.write_ptr);
	mbedtls_sha512_update(&context->th2_context, (uint8_t *)&rsp_msg.header,
			sizeof(rsp_msg.header));
	mbedtls_sha512_update(&context->th2_context, rsp_msg.buffer.data, rsp_msg.buffer.write_ptr);
	mbedtls_sha512_finish(&context->th2_context, hash);
	mbedtls_sha512_free(&context->th2_context);
	SPDM_DBG_HEXDUMP(hash, sizeof(hash), "Hash for key");

	ret = spdm_gen_session_key_iv(context, session, SPDM_RESPONSE_MODE, hash, false);
	if (ret) {
		LOG_ERR("Failed to generate session key for rep side");
		goto cleanup;
	}
	ret = spdm_gen_session_key_iv(context, session, SPDM_REQUEST_MODE, hash, false);
	if (ret) {
		LOG_ERR("Failed to generate session key for rsp side");
		goto cleanup;
	}
	session->connection_state = SPDM_STATE_SESSION_ESTABLISHED;

	session->afm_index = index & 0xff;
	session->last_access_time = k_uptime_get();
	session->local_capabilities_flag = context->local.capabilities.flags;
	session->remote_capabilities_flag = context->remote.capabilities.flags;
	copy_remote_cert(context, session);
	ret = spdm_buffer_resize(session->message_a, context->message_a.write_ptr);
	spdm_buffer_append_array(session->message_a, context->message_a.data,
		context->message_a.write_ptr);
	LOG_INF("Length of message_a = %d", session->message_a->write_ptr);
	ret = 0;

cleanup:
	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);

	return ret;
}

