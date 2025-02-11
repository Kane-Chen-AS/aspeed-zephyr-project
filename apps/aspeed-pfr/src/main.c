/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <build_config.h>
#include <zephyr/drivers/led.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/misc/aspeed/abr_aspeed.h>

#include "AspeedStateMachine/AspeedStateMachine.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

#define DEBUG_HALT() {				  \
		volatile int halt = 1;		  \
		while (halt) {			  \
			__asm__ volatile ("nop"); \
		}				  \
}

extern void aspeed_print_sysrst_info(void);

#if defined(CONFIG_LED_GPIO)
#if !DT_NODE_HAS_STATUS(DT_INST(0, gpio_leds), okay)
#error "no correct led gpio device"
#endif

#if DT_NODE_EXISTS(DT_NODELABEL(pfr_hb_led_out))
#define HB_LED_IDX DT_NODE_CHILD_IDX(DT_NODELABEL(pfr_hb_led_out))

void hbled_tick(struct k_timer *timer_id)
{
	static const struct device *led_dev = NULL;
	static bool tock = false;

	if (led_dev == NULL)
		led_dev = device_get_binding("leds");

	if (led_dev) {
		if (tock) {
			LOG_DBG("PFR_SW_HBLED_OFF");
			led_off(led_dev, HB_LED_IDX);
			tock = false;
		} else {
			LOG_DBG("PFR_SW_HBLED_ON");
			led_on(led_dev, HB_LED_IDX);
			tock = true;
		}
	}
}

K_TIMER_DEFINE(hbled_timer, hbled_tick, NULL);
#endif
#endif

void main(void)
{
	LOG_INF("*** ASPEED_PFR version v%02d.%02d-dev Board:%s ***",
			PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR, CONFIG_BOARD);
#if defined (CONFIG_BOARD_AST2700_DCSCM)
	LOG_WRN("FOR AST2700-A1 DCSCM Board Bring Up");
	LOG_WRN("v1 - IGNORE RSTIND");
	LOG_WRN("v2 - Mailbox I2C5 -> I2C0");
	LOG_WRN("v3 - Remove SGPIO workaround");
	LOG_WRN("v4 - I3C DBG LOG");
	LOG_WRN("v5 - Zephyr upgrade v3.7.0");
	LOG_WRN("v6 - Mailbox I2C1 -> I2C0");
	LOG_WRN("v7~8 - Add ast2700a0");
	LOG_WRN("v9 - Update SGPIO table");
#endif
#if 0
	// Halting for JTAG debug
	disable_abr_wdt();
	DEBUG_HALT();
#endif

	aspeed_print_sysrst_info();

#if defined(CONFIG_LED_GPIO) && DT_NODE_EXISTS(DT_NODELABEL(pfr_hb_led_out))
	k_timer_start(&hbled_timer, K_MSEC(500), K_MSEC(500));
#endif

	AspeedStateMachine();
}
