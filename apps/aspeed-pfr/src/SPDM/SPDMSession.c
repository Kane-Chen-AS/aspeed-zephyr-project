/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include "SPDM/SPDMContext.h"
#include "SPDM/SPDMCommon.h"
#include "SPDM/SPDMDefinitions.h"
#include "SPDM/SPDMSession.h"
#include <stdlib.h>
#include <mbedtls/md.h>

LOG_MODULE_DECLARE(spdm_rsp, CONFIG_LOG_DEFAULT_LEVEL);

static const uint8_t spdm_version_str_11[] = SPDM_VERSION_DETAIL_11;
static const size_t spdm_version_str_11_len = sizeof(spdm_version_str_11);
static const uint8_t spdm_version_str_12[] = SPDM_VERSION_DETAIL_12;
static const size_t spdm_version_str_12_len = sizeof(spdm_version_str_12);

static struct spdm_session_context session_table[SPDM_MAX_SESSION] = {
};

uint8_t get_free_session_slot(void)
{
	for (uint8_t i = 0; i < SPDM_MAX_SESSION; ++i) {
		if (session_table[i].valid_session == false) {
			if (session_table[i].session_id)
				spdm_session_release(&session_table[i]);
			return i;
		} else {
			/* to validate session is expired or not */
			if (valid_session(&session_table[i]) == false)
				return i;
		}
	}
	return SPDM_NO_EMPTY_SESSION_CODE;
}

/*
 * When SPDM requester/responder receives a finish request,
 * a secure session isn't established completely yet
 * so finish request doesn't carry any session id info.
 * It causes a problem to map the session info in the code.
 * This implementation tries to get a session info via session state
 * It has a risk to map a wrong session info if there are two or
 * more concurrent sessions are creating.
 */
struct spdm_session_context *find_pending_session(void)
{
	for (size_t i = 0; i < SPDM_MAX_SESSION; ++i) {
		if (session_table[i].valid_session &&
			(session_table[i].connection_state != SPDM_STATE_SESSION_ESTABLISHED))
			return &session_table[i];
	}
	return NULL;
}

struct spdm_session_context *spdm_session_create(uint8_t slot_id, uint16_t req_id, uint16_t rsp_id, uint8_t heartbeatperiod)
{
	struct spdm_session_context *session = NULL;

	LOG_INF("Create session with id (%04x%04x)", req_id, rsp_id);

	if (slot_id >= SPDM_MAX_SESSION) {
		LOG_ERR("Invalid slot id (%d)", slot_id);
		return NULL;
	}
	session = &session_table[slot_id];
	session->valid_session = true;
	session->session_id = (req_id << 16) | (rsp_id << 0);
	session->heartbeatperiod = heartbeatperiod;
	session->last_access_time = k_uptime_get();
	session->connection_state = SPDM_STATE_CHANLLENGED;
	session->message_a = malloc(sizeof(struct spdm_buffer));
	if (session->message_a == NULL) {
		LOG_ERR("Failed to allocate memory for message_a (%d)", sizeof(struct spdm_buffer));
		return NULL;
	}
	spdm_buffer_init(session->message_a, 0);

	return session;
}

bool valid_session(struct spdm_session_context *session)
{
	uint32_t current_time, time_diff;
	uint8_t heartbeatperiod = session->heartbeatperiod;

	current_time = k_uptime_get();
	time_diff = current_time - session->last_access_time;
	time_diff /= 1000; // mini-second to second

	/*
	 * Heartbeat period value 0 means the heartbeat feature is not available in this session.
	 */
	if (heartbeatperiod == 0)
		return true;

	/* Per SPDM Spec., to terminate a session if there is no incoming packet
	 * in twice heartbeatperiod
	 */
	if (time_diff > (heartbeatperiod * 2)) {
		LOG_ERR("Session [%x] was expired over %d seconds, to release session info",
			session->session_id, time_diff);
		spdm_session_release(session);
		return false;
	}

	return true;
}

struct spdm_session_context *spdm_session_get(uint32_t session_id)
{
	struct spdm_session_context *session = NULL;

	for (size_t i = 0; i < SPDM_MAX_SESSION; ++i) {
		if (session_table[i].valid_session &&
			session_table[i].session_id == session_id) {
			if (valid_session(&session_table[i]))
				session = &session_table[i];
			break;
		}
	}

	return session;
}

struct spdm_session_context *spdm_session_get_by_idx(uint8_t idx)
{
	struct spdm_session_context *session = NULL;

	for (size_t i = 0; i < SPDM_MAX_SESSION; ++i) {
		if (session_table[i].valid_session &&
			session_table[i].afm_index == idx) {
			if (valid_session(&session_table[i]))
				session = &session_table[i];
			break;
		}
	}

	return session;
}

void spdm_session_release(struct spdm_session_context *context)
{
	LOG_INF("Release session [%x]", context->session_id);
	if (context->cert_data) {
		LOG_INF("Release cert_data");
		free(context->cert_data);
	}
	if (context->rsp_hmac) {
		LOG_DBG("Release rsp_hmac");
		mbedtls_md_free(context->rsp_hmac);
		free(context->rsp_hmac);
	}
	if (context->req_hmac) {
		LOG_DBG("Release req_hmac");
		mbedtls_md_free(context->req_hmac);
		free(context->req_hmac);
	}
	if (context->master_secret) {
		LOG_DBG("Release master_secret");
		free(context->master_secret);
	}
	if (context->master_secret_req) {
		LOG_DBG("Release master_secret_req");
		free(context->master_secret_req);
	}
	if (context->master_secret_rsp) {
		LOG_DBG("Release master_secret_rsp");
		free(context->master_secret_rsp);
	}
	if (context->handshake_secret) {
		LOG_DBG("Release handshake_secret");
		free(context->handshake_secret);
	}
	if (context->session_secret_req) {
		LOG_DBG("Release session_secret_req");
		free(context->session_secret_req);
	}
	if (context->session_secret_rsp) {
		LOG_DBG("Release session_secret_rsp");
		free(context->session_secret_rsp);
	}
	if (context->message_a) {
		LOG_DBG("Release message_a");
		spdm_buffer_release(context->message_a);
		free(context->message_a);
	}
	memset(context, 0, sizeof(struct spdm_session_context));
}

void spdm_disable_session(uint8_t index)
{
	struct spdm_session_context *session = NULL;

	session = spdm_session_get_by_idx(index);
	if (session)
		session->valid_session = 0;
	else
		LOG_INF("No session for index [%d]", index);
}

void spdm_session_init_session_table(void)
{
	for (size_t i = 0; i < SPDM_MAX_SESSION; ++i)
		spdm_session_release(&session_table[i]);

	memset(session_table, 0, sizeof(session_table));
}

struct spdm_session_context *spdm_session_get_from_table(int index)
{
	if (index >= SPDM_MAX_SESSION || index < 0)
		return NULL;
	return &session_table[index];
}

int spdm_bin_concat(void *ctx,
		uint8_t *str1, size_t str1_len,
		uint8_t *str2, size_t str2_len,
		uint8_t *output, size_t *output_len, uint16_t msg_len)
{
	struct spdm_context *context = (struct spdm_context *)ctx;
	uint8_t *ptr = output;

	if (*output_len < 1 + spdm_version_str_11_len + str1_len + str2_len) {
		LOG_ERR("Output buffer is not enough");
		return -1;
	}

	memcpy(ptr, &msg_len, sizeof(uint16_t));
	ptr += sizeof(uint16_t);

	if (context->local.version.version_number_selected == SPDM_VERSION_11) {
		memcpy(ptr, spdm_version_str_11, spdm_version_str_11_len - 1);
		ptr += (spdm_version_str_11_len - 1);
	} else {
		memcpy(ptr, spdm_version_str_12, spdm_version_str_12_len - 1);
		ptr += (spdm_version_str_12_len - 1);
	}

	if (str1) {
		memcpy(ptr, str1, str1_len);
		ptr += str1_len;
	}

	if (str2) {
		memcpy(ptr, str2, str2_len);
		ptr += str2_len;
	}
	*output_len = 1 + spdm_version_str_11_len + str1_len + str2_len;

	return 0;
}
