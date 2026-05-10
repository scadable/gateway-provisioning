// boot_decision.h — does this chip have everything it needs to talk to
// the SCADABLE cloud, or do we need the customer to provision it?
//
// SCADABLE 2026 · Apache-2.0

#ifndef GATEWAY_PROVISIONING_BOOT_DECISION_H
#define GATEWAY_PROVISIONING_BOOT_DECISION_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The mode `decide_mode()` returns drives what `app_main()` does next.
 *
 *   MODE_AP       - bring up SoftAP + captive portal so the customer
 *                   can enter WiFi credentials. We end up here when
 *                   either (a) no creds saved, (b) no device cert in
 *                   NVS (chip wasn't properly flashed), (c) saved
 *                   creds don't connect, or (d) WiFi works but the
 *                   SCADABLE health endpoint is unreachable.
 *
 *   MODE_OTA_PULL - everything looks good. WiFi joined, cloud
 *                   reachable, device cert present. Hand off to
 *                   libscadable, publish a "provisioned" status, and
 *                   wait for the customer firmware OTA.
 */
typedef enum {
    MODE_AP = 0,
    MODE_OTA_PULL = 1,
} provisioning_mode_t;

/**
 * Run all four checks in order and return a mode. This call may
 * block for up to CONFIG_SCADABLE_WIFI_CONNECT_TIMEOUT_SECS plus a
 * 5-second HTTP timeout (i.e. ~35s worst case) before returning
 * MODE_AP. A successful flow returns MODE_OTA_PULL in roughly 5-10
 * seconds.
 *
 * Side effects:
 *   - Initializes esp_netif + the WiFi driver in STA mode.
 *   - On success: leaves WiFi connected (cloud_check_run() takes over
 *     from here without re-doing the join).
 *   - On any failure: leaves WiFi disconnected and the driver
 *     stopped, so ap_provisioning_start() can re-init in AP mode
 *     cleanly.
 */
provisioning_mode_t decide_mode(void);

/**
 * Wipe the `wifi` NVS namespace (ssid + password). Called by the
 * recovery hook in main.c when GPIO0 is held at boot. Safe to call
 * before nvs_flash_init() — performs its own init if needed.
 */
void boot_decision_wipe_wifi_creds(void);

#ifdef __cplusplus
}
#endif

#endif  // GATEWAY_PROVISIONING_BOOT_DECISION_H
