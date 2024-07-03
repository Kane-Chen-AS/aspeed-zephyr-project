/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stddef.h>
#include "SPDM/SPDMBuffer.h"

#pragma once

#pragma pack(push, 1)
struct spdm_session_context {
	/* Requester_Id[31:16] + Responder_Id[15:0] */
	uint32_t session_id;

	/* AFM device list index */
	uint8_t afm_index;

	/* PFR as a requester or PFR as a Responder */
	uint8_t session_type;

	/* Session slot is occupied or not */
	uint8_t valid_session;

	/* SPDM version */
	uint8_t version;

	/* MCTP medium type */
	uint8_t medium;

	/* MCTP bus number */
	uint8_t bus;

	/* Medium dest address */
	uint8_t dst_sa;

	/* MCTP dest eid */
	uint8_t dst_eid;

	/* Secret length */
	uint8_t secret_len;

	/* DHE secret or PSKHint */
	uint8_t shared_secret[128];

	/* Message_a for requester */
	struct spdm_buffer *message_a;

	/* Handshake secret */
	enum SPDM_CONNECTION_STATE connection_state;

	/* Heartbeat period for this session, value 0 means this session doesn't support heartbeat */
	uint8_t heartbeatperiod;

	/* Capabilities flags */
	uint32_t local_capabilities_flag;
	uint32_t remote_capabilities_flag;

	/* Remote certificate for measurement verification */
	uint8_t *cert_data;
	uint32_t cert_data_len;

	/* handshake secret */
	void *handshake_secret;

	/* Master secret */
	void *master_secret;

	/* Master secret for request side */
	void *master_secret_req;

	/* Master secret for respond side */
	void *master_secret_rsp;

	/* Handshake/session encryption key for requester */
	uint8_t encryption_key_req[32];

	/* Handshake/session encryption salt for requester */
	uint8_t encryption_salt_req[12];

	/* Handshake/session encryption key for responder */
	uint8_t encryption_key_rsp[32];

	/* Handshake/session encryption salt for responder */
	uint8_t encryption_salt_rsp[12];

	/* session secret for request side */
	void *session_secret_req;

	/* session secret for respond side */
	void *session_secret_rsp;

	/* Handshake encryption data sequence number for responder */
	uint64_t sequence_number_req;

	/* Handshake encryption data sequence number for responder */
	uint64_t sequence_number_rsp;

	/* Request hmac context */
	void *req_hmac;

	/* Response hmac context */
	void *rsp_hmac;

	/* The last time to use this session */
	uint64_t last_access_time;
};
#pragma pack(pop)

#define SPDM_MAX_SESSION 5
#define SPDM_SESSION_ID_BASE 0x0101
#define SPDM_NO_EMPTY_SESSION_CODE 0xef
/*
 * In Spec. 814910, when session encrypted or decrypted
 * blocks counter reaches the DPA threshold (10K packets),
 * the secure channel must be re-keyed
 */
#define MAX_SESSION_REKEY_COUNT 10000

int spdm_bin_concat(void *ctx,
		uint8_t *str1, size_t str1_len,
		uint8_t *str2, size_t str2_len,
		uint8_t *output, size_t *output_len, uint16_t msg_len);

struct spdm_session_context *spdm_session_create(uint8_t slot_id, uint16_t req_id, uint16_t rsp_id, uint8_t heartbeatperiod);
struct spdm_session_context *spdm_session_get(uint32_t session_id);
struct spdm_session_context *spdm_session_get_by_idx(uint8_t idx);
struct spdm_session_context *spdm_session_get_from_table(int index);
void spdm_session_release(struct spdm_session_context *context);
uint8_t get_free_session_slot(void);
void spdm_disable_session(uint8_t index);
bool valid_session(struct spdm_session_context *session);
struct spdm_session_context *find_pending_session(void);

/* DSP0274: Table 91 Key schedule:
 * Variable	Definition
 * Salt_0	A zero-filled array of `Hash.length` length
 * 0_filled	A zero-filled array of `Hash.length` length.
 * bin_str0	`BinConcat(Hash.length, Version, "derived", NULL)`
 * bin_str1	`BinConcat(Hash.length, Version, "req hs data", TH1)`
 * bin_str2	`BinConcat(Hash.length, Version, "rsp hs data", TH1)`
 * bin_str3	`BinConcat(Hash.length, Version, "req app data", TH2)`
 * bin_str4	`BinConcat(Hash.length, Version, "rsp app data", TH2)`
 * DHE Secret	This shall be the secret derived from `KEY_EXCHANGE/KEY_EXCHANGE_RSP`
 *
 * TH1:
 * 1. `VCA`
 * 2. Hash of the specified certificate chain in DER format (that is, `Param 2` of `KEY_EXCHANGE`
 *    or hash of the public key in it's provisioned format, if a certificate is not used
 * 3. `[KEY_EXCHANGE].*`
 * 4. `KEY_EXCHANGE_RSP.*` except the ResponderVerifyData field
 *
 * TH2:
 * 1. `VCA`
 * 2. Hash of the specified certificate chain in DER format (that is, `Param 2` of `KEY_EXCHANGE`
 *    or hash of the public key in it's provisioned format, if a certificate is not used
 * 3. `[KEY_EXCHANGE].*`
 * 4. `[KEY_EXCHANGE_RSP].*`
 * 5. Hash of the specified certificate chain in DER format (that is, `Param 2` of `FINISH`)
 *    or hash of the public key in its provisioned format, if a certificate is not used.
 *    (Valid only in mutual authentication)
 * 6. `[FINISH].*`
 * 7. `[FINISH_RSP].*`
 *
 * Generate Handshake Secret (DSP0274 Clause 755 Figure 27 Key schedule)
 * handshake_secret = HMAC-Hash(Salt_0, DHE_Secret)
 * Response Direction Handshake Secret = HKDF-Expand(handshake_secret, bin_str2, hash.length)
 * Salt_1 = HKDF-Expand(handshake_secret, bin_str0, hash.length
 * Master-Secret = HMAC-Hash(Salt_1, 0_filled)
 * Responder Direction Data Secret = HKDF-Expand(Master-Secret, bin_str4, hash.length
 *
 */


