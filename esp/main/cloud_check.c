// cloud_check.c — libscadable hand-off: publish "provisioned", wait
// for OTA.
// SCADABLE 2026 · Apache-2.0
//
// At this point boot_decision has confirmed: WiFi up, cloud
// reachable, device cert in NVS. We hand off to libscadable to do
// the rest.
//
// What we do:
//   1. scadable_init(NULL) — libscadable reads namespace + cert from
//      NVS (set at flash time by the dashboard).
//   2. Register an event callback so we know when MQTT comes up.
//   3. scadable_connect() — non-blocking; libscadable spins up its
//      internal task and starts the TLS handshake.
//   4. Wait for SCADABLE_EVT_CONNECTED, then publish a one-shot
//      `{"state":"provisioned","reason":"awaiting_customer_firmware"}`
//      status message on SCADABLE_CH_EVENTS so the cloud's gateway
//      record flips to `provisioned`.
//   5. Idle. libscadable's OTA hook auto-subscribes to the OTA
//      command topic; when the cloud's existing release.apply flow
//      pushes the customer firmware URL, libscadable downloads it,
//      validates it, swaps OTA partitions, and reboots — at which
//      point we (the factory firmware) sleep until something goes
//      wrong and the bootloader falls back to us.
//
// Failure modes: any libscadable error → log + return so main.c can
// fall back to AP mode. We don't try to recover in-place; the
// bootloader-fallback path is the recovery story.

#include "cloud_check.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

#include "scadable.h"

static const char *TAG = "scadable.cloud";

#define EVT_CONNECTED_BIT    BIT0
#define EVT_FATAL_ERROR_BIT  BIT1

static EventGroupHandle_t s_evt_group;

static void on_scadable_event(scadable_event_t evt, void *user)
{
    (void)user;
    switch (evt.type) {
        case SCADABLE_EVT_CONNECTED:
            ESP_LOGI(TAG, "libscadable: CONNECTED (recovered=%lu)",
                     (unsigned long)evt.connected.recovered_count);
            xEventGroupSetBits(s_evt_group, EVT_CONNECTED_BIT);
            break;

        case SCADABLE_EVT_DISCONNECTED:
            ESP_LOGW(TAG, "libscadable: DISCONNECTED — auto-reconnect will retry");
            break;

        case SCADABLE_EVT_PUBLISHED:
            ESP_LOGD(TAG, "libscadable: PUBACK msg_id=%ld",
                     (long)evt.published.msg_id);
            break;

        case SCADABLE_EVT_OTA_AVAILABLE:
            // libscadable applies the OTA itself and reboots. We just
            // log this so it's visible in the serial log if a
            // customer is watching the device come online.
            ESP_LOGI(TAG, "libscadable: OTA_AVAILABLE — customer firmware "
                          "version=%s. Reboot incoming.",
                     evt.ota_available.new_version
                         ? evt.ota_available.new_version
                         : "(unknown)");
            break;

        case SCADABLE_EVT_ENV_CHANGED:
            // Provisioning firmware doesn't read any env vars, but
            // log so the dashboard env-update path is visible.
            ESP_LOGI(TAG, "libscadable: ENV_CHANGED key=%s",
                     evt.env_changed.key ? evt.env_changed.key : "(?)");
            break;

        case SCADABLE_EVT_ERROR:
            ESP_LOGE(TAG,
                     "libscadable: ERROR code=%d esp_tls=%ld mbedtls=%ld "
                     "verify_flags=0x%lx retriable=%d",
                     (int)evt.error.code,
                     (long)evt.error.esp_tls_err,
                     (long)evt.error.mbedtls_err,
                     (unsigned long)evt.error.cert_verify_flags,
                     (int)evt.error.retriable);
            // Only flag fatal (non-retriable) errors. Transient TLS /
            // network blips are libscadable's problem to manage via
            // its own backoff.
            if (!evt.error.retriable) {
                xEventGroupSetBits(s_evt_group, EVT_FATAL_ERROR_BIT);
            }
            break;
    }
}

void cloud_check_run(void)
{
    s_evt_group = xEventGroupCreate();

    scadable_err_t err = scadable_init(NULL);
    if (err != SCADABLE_OK) {
        ESP_LOGE(TAG, "scadable_init failed: %s", scadable_strerror(err));
        return;
    }

    scadable_on_event(on_scadable_event, NULL);

    err = scadable_connect();
    if (err != SCADABLE_OK) {
        ESP_LOGE(TAG, "scadable_connect failed: %s", scadable_strerror(err));
        return;
    }

    // Wait up to 60 seconds for CONNECTED. libscadable's auto-
    // reconnect retries internally, so this timeout is just for the
    // initial happy path; if 60s isn't enough, something is wrong
    // (cert revoked, broker outage, namespace deleted) and AP mode
    // is the right fallback.
    EventBits_t bits = xEventGroupWaitBits(
        s_evt_group,
        EVT_CONNECTED_BIT | EVT_FATAL_ERROR_BIT,
        pdFALSE, pdFALSE,
        pdMS_TO_TICKS(60000));

    if (!(bits & EVT_CONNECTED_BIT)) {
        ESP_LOGE(TAG, "Did not connect within 60s (bits=0x%x). Falling back.", (int)bits);
        scadable_disconnect();
        return;
    }

    // Build the status payload. We include the device's own MAC
    // (uppercase no separators) as a sanity field — handy when
    // debugging which physical chip flipped to provisioned.
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char mac_str[13];
    snprintf(mac_str, sizeof(mac_str), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    char payload[160];
    int n = snprintf(payload, sizeof(payload),
                     "{\"state\":\"provisioned\","
                     "\"reason\":\"awaiting_customer_firmware\","
                     "\"firmware\":\"gateway-provisioning\","
                     "\"mac\":\"%s\"}",
                     mac_str);
    if (n < 0 || n >= (int)sizeof(payload)) {
        ESP_LOGE(TAG, "payload render failed");
        scadable_disconnect();
        return;
    }

    err = scadable_publish(SCADABLE_CH_EVENTS, payload, (size_t)n, /*qos*/ 1);
    if (err != SCADABLE_OK) {
        ESP_LOGE(TAG, "publish provisioned status failed: %s",
                 scadable_strerror(err));
        // Don't bail — libscadable is still connected and the OTA
        // hook is still subscribed. The cloud just won't see the
        // status flip until the next time we get here.
    } else {
        ESP_LOGI(TAG, "Published provisioned status: %s", payload);
    }

    ESP_LOGI(TAG, "Idle — waiting for customer firmware OTA. "
                  "libscadable handles keepalive + the OTA pull.");

    // Park the calling task forever. libscadable runs on its own
    // FreeRTOS task; when the OTA arrives it'll reboot the chip.
    // Fatal errors set the flag and let us exit so main.c can fall
    // back to AP mode.
    while (true) {
        EventBits_t b = xEventGroupWaitBits(
            s_evt_group, EVT_FATAL_ERROR_BIT, pdFALSE, pdFALSE,
            pdMS_TO_TICKS(60000));
        if (b & EVT_FATAL_ERROR_BIT) {
            ESP_LOGE(TAG, "Fatal libscadable error — cleaning up and falling back to AP mode");
            scadable_disconnect();
            return;
        }
        // Periodic heartbeat log so a developer watching the serial
        // monitor can see we're alive.
        ESP_LOGI(TAG, "Still idle; libscadable state=%d", (int)scadable_state());
    }
}
