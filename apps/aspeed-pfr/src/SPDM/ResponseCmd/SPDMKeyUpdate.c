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

int spdm_handle_key_update(void *ctx, void *req, void *rsp, uint32_t *session_id)
{
	LOG_INF("Enter KEY_UPDATE");
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;
	struct spdm_session_context *session;
	int ret;

	LOG_HEXDUMP_INF(&req_msg->header, 4, "KEY_UPDATE Header");
	LOG_HEXDUMP_INF(req_msg->buffer.data, req_msg->buffer.write_ptr, "KEY_UPDATE");

	if (session_id == NULL) {
		LOG_ERR("Session id should not be NULL in this stage");
		return -1;
	} else
		session = spdm_session_get(*session_id);

	if (session == NULL) {
		LOG_ERR("Failed to find session info");
		return -1;
	}

	switch (req_msg->header.param1) {
	case SPDM_KEY_UPDATE_RESERVED:
	case SPDM_KEY_UPDATE_VERIFY_KEY:
		ret = 0;
		break;
	case SPDM_KEY_UPDATE_SINGLE:
		ret = spdm_update_key(context, session, SPDM_REQUEST_MODE);
		break;
	case SPDM_KEY_UPDATE_BOTH:
		ret = spdm_update_key(context, session, SPDM_REQUEST_MODE);
		if (ret)
			break;
		ret = spdm_update_key(context, session, SPDM_RESPONSE_MODE);
		break;
	default:
		LOG_ERR("Unsupported operation %x", req_msg->header.param1);
		return -1;
	}

	if (ret) {
		LOG_ERR("Key update operation (%x) is failed, ret = %x",
			req_msg->header.param1, ret);
		return ret;
	}

	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_KEY_UPDATE_ACK;
	rsp_msg->header.param1 = req_msg->header.param1;
	rsp_msg->header.param2 = req_msg->header.param2;

	rsp_msg->buffer.write_ptr = 0;
	return 0;
}
