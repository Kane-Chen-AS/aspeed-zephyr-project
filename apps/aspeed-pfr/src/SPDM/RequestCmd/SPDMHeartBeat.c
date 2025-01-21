/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_heartbeat(void *ctx, uint32_t session_id)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret;

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_HEARTBEAT;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

	spdm_buffer_init(&req_msg.buffer, 0);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	LOG_HEXDUMP_INF(&req_msg.header, sizeof(req_msg.header), "HEARTBEAT HEADER:");
	ret = spdm_send_request_enc(context, &req_msg, &rsp_msg, session_id);
	if (ret != 0) {
		LOG_ERR("HEARTBEAT failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_HEARTBEAT_ACK) {
		LOG_ERR("Expecting HEARTBEAT_ACK message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (ret < 0)
		LOG_HEXDUMP_ERR(&rsp_msg.header, sizeof(rsp_msg.header), "HEARTBEAT HEADER:");

	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}

int spdm_send_heartbeat(struct spdm_session_context *session)
{
	struct spdm_context *context = NULL;
	int ret;

	context = spdm_context_create();
	if (context == NULL) {
		LOG_ERR("Failed to allocate SPDM Context");
		return -1;
	}
	ret = init_requester_context(context,
			session->medium,
			session->bus,
			session->dst_sa,
			session->dst_eid,
			false);

	if (ret == false) {
		LOG_ERR("Init requester context failed");
		return -1;
	}

	context->local.version.version_number_selected = session->version;
	LOG_DBG("Send heartbeat for session [%x]", session->session_id);
	ret = spdm_heartbeat(context, session->session_id);
	spdm_context_release(context);
	if (ret) {
		LOG_ERR("Send heartbeat failed");
		spdm_session_release(session);
		return ret;
	}

	return 0;
}

