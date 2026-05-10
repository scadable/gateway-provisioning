// cloud_check.h — libscadable hand-off: publish "provisioned", wait
// for OTA.
//
// SCADABLE 2026 · Apache-2.0

#ifndef GATEWAY_PROVISIONING_CLOUD_CHECK_H
#define GATEWAY_PROVISIONING_CLOUD_CHECK_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize libscadable, connect to the broker, publish a one-shot
 * `{"state":"provisioned","reason":"awaiting_customer_firmware"}`
 * status event, and idle while libscadable's OTA hook waits for the
 * cloud to push the customer firmware. When the OTA arrives,
 * libscadable swaps slots and reboots us into the new image — so
 * this function only returns if something went wrong.
 *
 * Pre-conditions:
 *   - WiFi already connected (decide_mode() left STA up).
 *   - NVS namespace `scadable_certs` populated with `device_cert` +
 *     `device_key` (libscadable reads these in scadable_init()).
 *
 * Returns: never on success. On error, returns and main.c falls back
 * to AP mode so the customer can intervene.
 */
void cloud_check_run(void);

#ifdef __cplusplus
}
#endif

#endif  // GATEWAY_PROVISIONING_CLOUD_CHECK_H
