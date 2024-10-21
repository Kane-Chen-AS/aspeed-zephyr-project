/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <sys/types.h>
#pragma once

/* Enablie for I3C Attestation */
#define SPDM_REQ_EVT_ATTESTED_CPU	BIT(4)
#define SPDM_REQ_EVT_T0_I3C		BIT(3)
/* Timer tick */
#define SPDM_REQ_EVT_TICK		BIT(2)
/* System in T0 */
#define SPDM_REQ_EVT_T0			BIT(1)
/* Enable attestation by UFM (Set in AspeedStateMachine::do_init once) */
#define SPDM_REQ_EVT_ENABLE		BIT(0)

int spdm_send_request(void *ctx, void *req_msg, void *rsp_msg);
int spdm_send_request_enc(void *ctx, void *req, void *rsp, uint32_t session_id);
void spdm_enable_attester(void);
void spdm_run_attester(void);
void spdm_run_attester_i3c(void);
void spdm_stop_attester(void);
uint32_t spdm_get_attester(void);
off_t *spdm_get_afm_list(void);
