/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

int spdm_get_version(void *ctx);
int spdm_get_capabilities(void *ctx);
int spdm_negotiate_algorithms(void *ctx);
int spdm_get_digests(void *ctx);
int spdm_get_certificate(void *ctx, uint8_t slot_id);
int spdm_challenge(void *ctx, uint8_t slot_id, uint8_t measurements);
int spdm_get_measurements(void *ctx,
	uint8_t request_attribute, uint8_t measurement_operation,
	uint8_t *number_of_blocks,
	void *possible_measurements, uint32_t session_id);
int spdm_key_exchange(void *ctx, uint8_t *mutualauth, struct spdm_session_context **session_tmp);
int spdm_get_Encap(void *ctx);
int spdm_finish(void *ctx, uint8_t mutualauth, int index);
int spdm_heartbeat(void *ctx, uint32_t session_id);
int spdm_send_heartbeat(struct spdm_session_context *session);
int spdm_end(void *ctx, uint32_t session_id);
