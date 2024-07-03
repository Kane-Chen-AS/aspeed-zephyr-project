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

int spdm_handle_heartbeat(void *ctx, void *req, void *rsp, uint32_t *session_id)
{
	LOG_INF("Enter HEARTBEAT %x", *session_id);

	struct spdm_message *req_msg = (struct spdm_message *)req;
	struct spdm_message *rsp_msg = (struct spdm_message *)rsp;

	SPDM_DBG_HEXDUMP(&req_msg->header, 4, "HEARTBEAT Header");
	SPDM_DBG_HEXDUMP(req_msg->buffer.data, req_msg->buffer.write_ptr, "HEARTBEAT");

	rsp_msg->header.spdm_version = req_msg->header.spdm_version;
	rsp_msg->header.request_response_code = SPDM_RSP_HEARTBEAT_ACK;
	rsp_msg->header.param1 = 0;
	rsp_msg->header.param2 = 0;

	rsp_msg->buffer.write_ptr = 0;
	SPDM_DBG_HEXDUMP(&rsp_msg->header, 4, "HEARTBEAT ACK Header");
	return 0;
}
