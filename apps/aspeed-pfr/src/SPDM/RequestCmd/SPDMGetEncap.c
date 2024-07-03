/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include "SPDM/SPDMCommon.h"

LOG_MODULE_DECLARE(spdm_req, CONFIG_LOG_DEFAULT_LEVEL);

typedef enum {
	SPDM_ENCAP_ERROR = -1,
	SPDM_ENCAP_CERT_VERIFIED = 0,
	SPDM_ENCAP_GET_CERT_CONT = 1
} SPDM_ENCAP_STATE;

int build_digest_rsp(struct spdm_context *context, struct spdm_message *req_msg)
{
	struct spdm_message_header header;
	uint8_t slot_mask, cert_count = 0;

	header.spdm_version = context->local.version.version_number_selected;
	header.request_response_code = SPDM_RSP_DIGESTS;
	header.param1 = 0;
	header.param2 = context->local.certificate.slot_mask;

	slot_mask = context->local.certificate.slot_mask;

	while (slot_mask) {
		cert_count++;
		slot_mask >>= 1;
	}
	LOG_INF("SlotMask = %x Count = %d", context->local.certificate.slot_mask,
			cert_count);

	spdm_buffer_init(&req_msg->buffer, cert_count * 48 + sizeof(header));
	spdm_buffer_append_array(&req_msg->buffer, &header, sizeof(header));
	slot_mask = context->local.certificate.slot_mask;
	cert_count = 0;
	while (slot_mask) {
		if (slot_mask & 0x01 && context->local.certificate.certs[cert_count].data != NULL) {
			// Certificate exists, calculate the digest with Certificate Chain Format
			// [0:1] Length: including all fields in this table
			// [2:3] Reserved
			// [4:H] Root Hash
			// [4+H:...] One or more ASN.1 DER-encoded X.509 v3 certificates
			//           where the first certificate is signed by the Root
			//           Certificate or is the Root Certificate itself and each
			//           subsequent certificate is signed by the preceding
			//           certificate. The last certificate is the leaf certificate.
			//           This field is big endian.
			uint8_t hash[48];

			mbedtls_sha512(context->local.certificate.certs[cert_count].data,
					context->local.certificate.certs[cert_count].size,
					hash,
					1 /* is384*/);
			LOG_HEXDUMP_DBG(hash, 48, "CERT DIGEST:");
			spdm_buffer_append_array(&req_msg->buffer, hash, 48);
		}
		cert_count++;
		slot_mask >>= 1;
	}
	return 0;
}

SPDM_ENCAP_STATE handle_get_cert(struct spdm_context *context, struct spdm_message *req_msg,
			struct spdm_message *rsp_msg)
{
	uint8_t ack_id, slot_id;
	struct spdm_message_header header;
	uint16_t offset, length;

	spdm_buffer_get_u8(&rsp_msg->buffer, &ack_id);
	spdm_buffer_get_reserved(&rsp_msg->buffer, 3);

	if (rsp_msg->buffer.size == 4) {
		LOG_INF("Certificate verified");
		return SPDM_ENCAP_CERT_VERIFIED;
	}
	spdm_buffer_get_array(&rsp_msg->buffer, &header, sizeof(header));

	if (context->local.version.version_number_selected != header.spdm_version) {
		LOG_ERR("Version is not matched");
		return SPDM_ENCAP_ERROR;
	}
	if (header.request_response_code != SPDM_REQ_GET_CERTIFICATE) {
		LOG_ERR("Request code is invalid %x", header.request_response_code);
		return SPDM_ENCAP_ERROR;
	}
	slot_id = header.param1 & 0x7;

	spdm_buffer_get_u16(&rsp_msg->buffer, &offset);
	spdm_buffer_get_u16(&rsp_msg->buffer, &length);

	spdm_buffer_release(&req_msg->buffer);

	uint16_t portion_length = 0x100;
	uint16_t cert_size = context->local.certificate.certs[slot_id].size;

	LOG_HEXDUMP_INF(&rsp_msg->header, sizeof(rsp_msg->header), "Rsp header");

	req_msg->header.spdm_version = context->local.version.version_number_selected;
	req_msg->header.request_response_code = SPDM_REQ_DELIVER_ENCAP_RESPONSE;
	req_msg->header.param1 = rsp_msg->header.param1;
	req_msg->header.param2 = 0;

	header.spdm_version = context->local.version.version_number_selected;
	header.request_response_code = SPDM_RSP_CERTIFICATE;
	header.param1 = slot_id;
	header.param2 = 0;

	if (cert_size > offset + portion_length) {
		spdm_buffer_init(&req_msg->buffer,
				2 + 2 + portion_length + sizeof(header));
		spdm_buffer_append_array(&req_msg->buffer, &header, sizeof(header));
		spdm_buffer_append_u16(&req_msg->buffer, portion_length);
		spdm_buffer_append_u16(&req_msg->buffer, cert_size - (offset + portion_length));
	} else {
		portion_length = cert_size - offset;
		spdm_buffer_init(&req_msg->buffer,
				2 + 2 + portion_length + sizeof(header));
		spdm_buffer_append_array(&req_msg->buffer, &header, sizeof(header));
		spdm_buffer_append_u16(&req_msg->buffer, portion_length);
		spdm_buffer_append_u16(&req_msg->buffer, 0);
	}

	spdm_buffer_append_array(&req_msg->buffer,
			context->local.certificate.certs[slot_id].data + offset,
			portion_length);

	return SPDM_ENCAP_GET_CERT_CONT;
}

// Get digest and certificate info for mutual authentication
int spdm_get_Encap(void *ctx)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	struct spdm_message req_msg, rsp_msg;
	int ret;

	req_msg.header.spdm_version = context->local.version.version_number_selected;
	req_msg.header.request_response_code = SPDM_REQ_DELIVER_ENCAP_RESPONSE;
	req_msg.header.param1 = 0;
	req_msg.header.param2 = 0;

	// Send digest response to responder
	build_digest_rsp(context, &req_msg);
	spdm_buffer_init(&rsp_msg.buffer, 0);

	ret = spdm_send_request(context, &req_msg, &rsp_msg);
	if (ret != 0) {
		LOG_ERR("Send digest response failed %x", ret);
		ret = -1;
		goto cleanup;
	} else if (rsp_msg.header.request_response_code != SPDM_RSP_ENCAP_RSP_ACK) {
		LOG_ERR("Expecting ENCAP_RSP_ACK message but got %02x Param[%02x,%02x]",
				rsp_msg.header.request_response_code,
				rsp_msg.header.param1,
				rsp_msg.header.param2);
		ret = -1;
		goto cleanup;
	}

	while ((ret = handle_get_cert(context, &req_msg, &rsp_msg)) ==
				SPDM_ENCAP_GET_CERT_CONT) {
		spdm_buffer_release(&rsp_msg.buffer);
		ret = spdm_send_request(context, &req_msg, &rsp_msg);
		if (ret != 0) {
			LOG_ERR("Send digest response failed %x", ret);
			ret = -1;
			goto cleanup;
		} else if (rsp_msg.header.request_response_code != SPDM_RSP_ENCAP_RSP_ACK) {
			LOG_ERR("Expecting ENCAP_RSP_ACK message but got %02x Param[%02x,%02x]",
					rsp_msg.header.request_response_code,
					rsp_msg.header.param1,
					rsp_msg.header.param2);
			ret = -1;
			goto cleanup;
		}
	}

cleanup:
	spdm_buffer_release(&req_msg.buffer);
	spdm_buffer_release(&rsp_msg.buffer);
	return ret;
}

