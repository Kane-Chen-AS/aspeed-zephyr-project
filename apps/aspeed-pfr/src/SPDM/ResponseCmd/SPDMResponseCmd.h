/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once
int spdm_handle_get_version(void *ctx, void *req, void *rsp);
int spdm_handle_get_capabilities(void *ctx, void *req, void *rsp);
int spdm_handle_negotiate_algorithms(void *ctx, void *req, void *rsp);
int spdm_handle_get_digests(void *ctx, void *req, void *rsp);
int spdm_handle_get_certificate(void *ctx, void *req, void *rsp);
int spdm_handle_challenge(void *ctx, void *req, void *rsp);
int spdm_handle_get_measurements(void *ctx, void *req, void *rsp);
int spdm_handle_key_exchange(void *ctx, void *req, void *rsp);
int spdm_handle_finish(void *ctx, void *req, void *rsp, uint32_t *session_id);
int spdm_handle_heartbeat(void *ctx, void *req, void *rsp, uint32_t *session_id);
int spdm_handle_end_session(void *ctx, void *req, void *rsp, uint32_t *session_id);
int spdm_handle_psk_exchange(void *ctx, void *req, void *rsp);
int spdm_handle_deliver_encap_rsp(void *ctx, void *req, void *rsp, uint32_t *session_id);
int spdm_handle_key_update(void *ctx, void *req, void *rsp, uint32_t *session_id);
