/*
 * Copyright (c) 2024 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#define SHA384_DIGEST_LENGTH            (48)

typedef struct {
	uint8_t index;
	uint8_t measurement_spec;
	uint16_t measurement_size;
} measurement_block_header;

typedef struct {
	uint32_t OperationalModeCapabilities;
	uint32_t OperationalModeState;
	uint32_t DeviceModeCapabilities;
	uint32_t DeviceModeState;
} measurement_device_mode_block;

#pragma pack(push, 1)
typedef struct {
	uint8_t value_type;
	uint16_t measurement_size;
} dmtf_measurement_spec_header;
#pragma pack(pop)

int get_measurement(void *context, uint8_t measurement_index,
	uint8_t *measurement_count, uint8_t *measurement,
	size_t *measurement_size);
void register_get_measurement(struct spdm_context *context);
