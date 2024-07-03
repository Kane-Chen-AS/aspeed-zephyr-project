/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMResponder.h"
#include "SPDM/ResponseCmd/SPDMResponseCmd.h"
#include "SPDM/SPDMSession.h"

#include <mbedtls/sha512.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <stdlib.h>

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

int spdm_handle_end_session(void *ctx, void *req, void *rsp, uint32_t *session_id)
{
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	struct spdm_session_context *session;

	if (session_id == NULL) {
		LOG_ERR("Session id should not be NULL in this stage");
		return -1;
	} else
		session = spdm_session_get(*session_id);

	LOG_INF("Handle End Session [%x]", *session_id);
	SPDM_DBG_HEXDUMP(&req_msg->header, 4, "END_SESSION Header");
	SPDM_DBG_HEXDUMP(req_msg->buffer.data, req_msg->buffer.write_ptr, "END_SESSION");

	if (session == NULL) {
		LOG_ERR("Failed to find session info");
		return -1;
	}

	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_END_SESSION_ACK;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	rsp_msg->buffer.write_ptr = 0;
	SPDM_DBG_HEXDUMP(&rsp_msg->header, 4, "END_SESSION ACK Header");
	return 0;
}
