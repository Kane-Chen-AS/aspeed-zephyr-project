/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once
#include <zephyr/kernel.h>

#define CERT_INFO_MAGIC_NUM               0x43455254    // hex of 'CERT'
#define SHA384_HASH_LENGTH                (384 / 8)
#define SHA256_HASH_LENGTH                (256 / 8)
#define ECDSA384_PRIVATE_KEY_SIZE         (SHA384_HASH_LENGTH + 1)
#define ECDSA384_PUBLIC_KEY_SIZE          (SHA384_HASH_LENGTH * 2 + 1)
#define CERT_CHAIN_SIZE                   0x1000

#define IS_CSR(info) (info.cert_type == CERT_REQ_TYPE)

enum cert_type {
	CERT_TYPE = 0,
	PUBLICKEY_TYPE,
	ECC_PRIVATEKEY_TYPE,
	CERT_REQ_TYPE,
	LAST_CERT_TYPE
};

typedef struct {
	uint32_t magic;
	uint32_t length;
	uint8_t data[CERT_CHAIN_SIZE];
	uint8_t hash[SHA256_HASH_LENGTH];
} PFR_CERT_INFO;

typedef struct {
	PFR_CERT_INFO cert;
	uint8_t pubkey[ECDSA384_PUBLIC_KEY_SIZE];
	uint8_t cert_type;
} PFR_DEVID_CERT_INFO;

