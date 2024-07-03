/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_end(void *ctx, uint32_t session_id)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret;

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_END_SESSION;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

	spdm_buffer_init(&req_msg.buffer, 0);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	LOG_HEXDUMP_INF(&req_msg.header, sizeof(req_msg.header), "END HEADER:");
	ret = spdm_send_request_enc(context, &req_msg, &rsp_msg, session_id);
	if (ret != 0) {
		LOG_ERR("HEARTBEAT failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_END_SESSION_ACK) {
		LOG_ERR("Expecting END_SESSION_ACK message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (ret < 0)
		LOG_HEXDUMP_ERR(&rsp_msg.header, sizeof(rsp_msg.header), "END SESSION ACK HEADER:");

	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}

