/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

int handle_spdm_mctp_message(void *context, void *buffer, size_t *length, uint32_t *session_id);
int decrypt_secure_content(void *context, void *buffer, size_t *length, uint32_t *session_id);
int encrypt_secure_content(void *context, uint8_t *rsp_hdr, uint8_t *rsp_body, size_t rsp_body_len, void *buffer, size_t *length, uint32_t *session_id);
int encrypt_spdm_content(struct spdm_context *context, struct spdm_message *spdm_msg, void *buffer, size_t *length, uint32_t *session_id);
