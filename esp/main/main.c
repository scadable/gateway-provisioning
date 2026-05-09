// main.c — entry point for the SCADABLE provisioning firmware.
// SCADABLE 2026 · Apache-2.0
//
// Lives in the `factory` partition forever. On every boot we:
//   1. Check for the recovery-button hold (GPIO0 low for N seconds)
//      and wipe saved WiFi creds if held — this lets a customer reset
//      a chip that moved networks without re-flashing.
//   2. Run boot_decision::decide_mode() which returns MODE_AP if the
//      chip is unprovisioned / its saved network is gone / the cloud
//      is unreachable, or MODE_OTA_PULL if everything is healthy and
//      we should hand off to libscadable.
//   3. Dispatch to the matching state machine. Both branches loop
//      forever from the firmware's perspective:
//        - AP mode reboots the chip from the HTTP handler when the
//          customer submits creds.
//        - OTA-pull mode reboots when libscadable swaps OTA slots
//          after the customer firmware lands.
//
// The defensive "if AP mode returns, fall through" path exists in
// case the AP timeout config (CONFIG_SCADABLE_AP_TIMEOUT_SECS) is
// non-zero and we time out; in that case we reboot, which re-runs
// the whole decision flow.

#include <stdio.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "ap_provisioning.h"
#include "boot_decision.h"
#include "cloud_check.h"

static const char *TAG = "scadable.provision";

// GPIO0 is the BOOT button on every ESP32 dev board and the standard
// recovery button on production hardware. The check is a simple busy
// loop — we don't care about precision here, just that the button
// stays low for the configured duration.
#define RECOVERY_BUTTON_GPIO 0

static void check_recovery_button(void)
{
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << RECOVERY_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);

    // Quick exit: if the button isn't pressed at all, don't waste 5s.
    if (gpio_get_level(RECOVERY_BUTTON_GPIO) != 0) {
        return;
    }

    ESP_LOGI(TAG, "BOOT button is held — checking for recovery hold (%ds)",
             CONFIG_SCADABLE_RECOVERY_BUTTON_HOLD_SECS);

    // Sample at 100ms; bail the moment the button is released.
    const int total_ticks = CONFIG_SCADABLE_RECOVERY_BUTTON_HOLD_SECS * 10;
    for (int i = 0; i < total_ticks; i++) {
        if (gpio_get_level(RECOVERY_BUTTON_GPIO) != 0) {
            ESP_LOGI(TAG, "Recovery button released early — ignoring");
            return;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGW(TAG, "Recovery hold confirmed — wiping saved WiFi creds");
    boot_decision_wipe_wifi_creds();

    ESP_LOGI(TAG, "Rebooting into AP mode");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
}

void app_main(void)
{
    printf("\n");
    printf("=============================================================\n");
    printf(" %s provisioning firmware\n", CONFIG_SCADABLE_COMPANY_NAME);
    printf(" Built " __DATE__ " " __TIME__ "\n");
    printf("=============================================================\n\n");

    // NVS underpins everything else — wifi creds, scadable_certs,
    // libscadable's own state. Initialize once here. We tolerate the
    // "no free pages" / "new version" cases by wiping and retrying;
    // production chips don't normally hit either, but development
    // chips re-flashed with different layouts do.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition needs erase (err=0x%x), re-initializing", err);
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed permanently: 0x%x — halting", err);
        // Don't reboot in a tight loop on a hardware failure.
        while (true) {
            vTaskDelay(pdMS_TO_TICKS(60000));
        }
    }

    // Recovery hook runs before the boot decision so a held button
    // forces us into AP mode regardless of saved state.
    check_recovery_button();

    provisioning_mode_t mode = decide_mode();

    switch (mode) {
        case MODE_OTA_PULL:
            ESP_LOGI(TAG, "Boot decision: OTA pull (chip is provisioned, cloud reachable)");
            cloud_check_run();
            // cloud_check_run() should not return. If it does, the
            // libscadable session crashed in a way we can't recover
            // from in-place, so fall through to AP mode and let the
            // customer intervene.
            ESP_LOGW(TAG, "cloud_check_run() returned — falling back to AP mode");
            // FALLTHROUGH

        case MODE_AP:
            ESP_LOGI(TAG, "Boot decision: AP mode (provisioning required)");
            ap_provisioning_start();
            // ap_provisioning_start() either reboots from the HTTP
            // handler (success path) or hits the optional timeout. If
            // it returns, restart the decision flow.
            ESP_LOGW(TAG, "ap_provisioning_start() returned — restarting");
            esp_restart();
            break;
    }
}
