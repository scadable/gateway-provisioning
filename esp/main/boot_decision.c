// boot_decision.c — "do I have wifi+internet+cert? then OTA. else AP."
// SCADABLE 2026 · Apache-2.0
//
// The decision is intentionally conservative: any failure on the
// happy path (missing creds, missing cert, can't connect, can't reach
// cloud) returns MODE_AP. Better to over-prompt the customer than
// silently fail and leave the device looking dead.
//
// All four checks are bundled here so main.c can stay a flat
// dispatcher. The function is allowed to take ~30s in the worst case
// (waiting for an unreachable WiFi network), which is fine — boot
// time isn't a tight constraint for a device that just came out of
// its box.

#include "boot_decision.h"

#include <string.h>

#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "boot_state.h"

static const char *TAG = "scadable.decision";

// libscadable's NVS namespace — we just check that the cert keys
// exist; we don't read or validate their contents (libscadable does
// that itself in scadable_init()).
#define NVS_NAMESPACE_CERTS "scadable_certs"
#define NVS_KEY_DEVICE_CERT "device_cert"
#define NVS_KEY_DEVICE_KEY  "device_key"

// `wifi_provisioning` component's standard NVS layout. Aligning with
// upstream lets a future BLE provisioning flow drop in cleanly.
#define NVS_NAMESPACE_WIFI  "wifi"
#define NVS_KEY_WIFI_SSID   "ssid"
#define NVS_KEY_WIFI_PASS   "password"

// Event group bits for the WiFi connect attempt.
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t s_wifi_event_group;

// Captured by the WiFi event handler so try_connect_saved_wifi() can
// report a structured outcome to boot_state. Default 0 → translates to
// "other" if we time out without ever seeing a disconnect event.
static uint8_t s_last_disconnect_reason = 0;

// Translate IDF wifi_err_reason_t into boot_state's coarser bucket.
// We only enumerate the cases the operator actually needs — anything
// else lands as BOOT_WIFI_ATTEMPT_OTHER.
static boot_wifi_attempt_t map_disconnect_reason(uint8_t reason)
{
    switch (reason) {
        case WIFI_REASON_NO_AP_FOUND:
            return BOOT_WIFI_ATTEMPT_NO_AP_FOUND;
        case WIFI_REASON_AUTH_FAIL:
        case WIFI_REASON_HANDSHAKE_TIMEOUT:
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
        case WIFI_REASON_MIC_FAILURE:
            return BOOT_WIFI_ATTEMPT_AUTH_FAILED;
        case WIFI_REASON_BEACON_TIMEOUT:
        case WIFI_REASON_ASSOC_EXPIRE:
            return BOOT_WIFI_ATTEMPT_TIMEOUT;
        default:
            return BOOT_WIFI_ATTEMPT_OTHER;
    }
}

void boot_decision_wipe_wifi_creds(void)
{
    // Defensive: idempotent. If NVS hasn't been initialized yet (e.g.
    // we're called before app_main's nvs_flash_init), do it here.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    nvs_handle_t handle;
    err = nvs_open(NVS_NAMESPACE_WIFI, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "wipe: nvs_open(wifi) failed: %s", esp_err_to_name(err));
        return;
    }
    nvs_erase_all(handle);
    nvs_commit(handle);
    nvs_close(handle);
    ESP_LOGI(TAG, "wifi NVS namespace wiped");
}

// Returns true iff key exists and has non-empty value in the namespace.
static bool nvs_key_present(const char *namespace, const char *key)
{
    nvs_handle_t handle;
    if (nvs_open(namespace, NVS_READONLY, &handle) != ESP_OK) {
        return false;
    }
    size_t len = 0;
    esp_err_t err = nvs_get_str(handle, key, NULL, &len);
    if (err != ESP_OK || len == 0) {
        // Try blob in case the value isn't a string.
        err = nvs_get_blob(handle, key, NULL, &len);
    }
    nvs_close(handle);
    return err == ESP_OK && len > 0;
}

// Read SSID + password from NVS. Returns true on success; out buffers
// are fixed size to match wifi_config_t fields (32 SSID + 64 pass).
static bool read_wifi_creds(char *ssid_out, size_t ssid_cap,
                            char *pass_out, size_t pass_cap)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE_WIFI, NVS_READONLY, &handle) != ESP_OK) {
        return false;
    }

    size_t len = ssid_cap;
    esp_err_t err = nvs_get_str(handle, NVS_KEY_WIFI_SSID, ssid_out, &len);
    if (err != ESP_OK) {
        nvs_close(handle);
        return false;
    }

    len = pass_cap;
    err = nvs_get_str(handle, NVS_KEY_WIFI_PASS, pass_out, &len);
    nvs_close(handle);
    if (err != ESP_OK) {
        // Open networks are valid — empty password is fine.
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            pass_out[0] = '\0';
            return true;
        }
        return false;
    }
    return true;
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        // No retries — boot_decision is a single attempt by design.
        // If it fails the customer needs to (re-)provision. Capture
        // the reason code so try_connect_saved_wifi() can report a
        // structured outcome to boot_state.
        if (event_data) {
            wifi_event_sta_disconnected_t *e = (wifi_event_sta_disconnected_t *)event_data;
            s_last_disconnect_reason = e->reason;
            ESP_LOGW(TAG, "WiFi disconnected (reason=%u)", e->reason);
        }
        xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

// Tear down the WiFi driver + STA netif so ap_provisioning_start()
// can call esp_netif_create_default_wifi_ap() (and its own
// esp_netif_create_default_wifi_sta() for APSTA scan support) without
// hitting the assert at wifi_default.c:388 ("netif != NULL"). That
// assert fires when the same default-wifi-sta slot is created twice
// without a destroy in between — exactly what was happening on every
// wrong-password boot before this fix (the chip rebooted in a tight
// loop and the customer could never recover without reflashing).
//
// Idempotent: every step tolerates "already torn down" so callers
// don't have to track whether they reached this point already.
//   - esp_wifi_stop / deinit return ESP_ERR_WIFI_NOT_INIT when the
//     driver was never started or was already deinit'd; that's fine.
//   - esp_netif_get_handle_from_ifkey returns NULL when the netif
//     was never created or was already destroyed; we just skip.
static void teardown_sta_for_ap_mode(void)
{
    // Stop + deinit WiFi first. If neither was ever called we'll get
    // ESP_ERR_WIFI_NOT_INIT back and that's fine — we're being
    // defensive so this helper can run from any of the three
    // "fall through to AP mode" sites in decide_mode().
    esp_wifi_stop();
    esp_wifi_deinit();

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif) {
        esp_netif_destroy_default_wifi(sta_netif);
        ESP_LOGI(TAG, "STA netif destroyed before AP fallback");
    }
}

// Attempts to join the saved network. Returns true on success.
// Leaves WiFi connected on success so cloud_check_run() can proceed
// without re-doing the join. On failure: stops + deinits the driver
// AND destroys the default STA netif (via teardown_sta_for_ap_mode)
// so ap_provisioning_start() can re-init in AP mode cleanly.
static bool try_connect_saved_wifi(const char *ssid, const char *password)
{
    s_wifi_event_group = xEventGroupCreate();
    s_last_disconnect_reason = 0;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t any_id_h, got_ip_h;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &any_id_h));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &got_ip_h));

    wifi_config_t wifi_cfg = {0};
    strncpy((char *)wifi_cfg.sta.ssid, ssid, sizeof(wifi_cfg.sta.ssid) - 1);
    strncpy((char *)wifi_cfg.sta.password, password, sizeof(wifi_cfg.sta.password) - 1);
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;  // accept any auth
    wifi_cfg.sta.pmf_cfg.capable = true;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Attempting to join saved network '%s' (timeout %ds)",
             ssid, CONFIG_SCADABLE_WIFI_CONNECT_TIMEOUT_SECS);

    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE,
        pdMS_TO_TICKS(CONFIG_SCADABLE_WIFI_CONNECT_TIMEOUT_SECS * 1000));

    bool success = (bits & WIFI_CONNECTED_BIT) != 0;
    if (success) {
        ESP_LOGI(TAG, "WiFi connected");
        // Persist success + the SSID so the next boot's /state can
        // show the operator which network we're on (and so AP-mode
        // boots on a network outage say "last seen MyHomeWiFi" rather
        // than "no SSID known").
        boot_state_record_wifi_attempt(BOOT_WIFI_ATTEMPT_SUCCESS, ssid);
        return true;
    }

    // Failure: classify the disconnect reason and persist it. The next
    // boot's captive portal will surface this so the operator knows
    // what went wrong on their last attempt.
    boot_wifi_attempt_t outcome;
    if (bits == 0) {
        // Timed out without ever getting WIFI_FAIL_BIT — driver never
        // produced a disconnect event. Treat as timeout.
        outcome = BOOT_WIFI_ATTEMPT_TIMEOUT;
    } else {
        outcome = map_disconnect_reason(s_last_disconnect_reason);
    }
    boot_state_record_wifi_attempt(outcome, NULL);

    ESP_LOGW(TAG, "WiFi connect failed (bits=0x%x reason=%u → %s) — tearing down for AP mode",
             (int)bits, s_last_disconnect_reason,
             boot_state_wifi_attempt_to_string(outcome));
    esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, got_ip_h);
    esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, any_id_h);
    teardown_sta_for_ap_mode();
    return false;
}

// One-shot HTTPS GET to the cloud health endpoint. Returns true iff
// status code is 200. Server cert is intentionally NOT pinned here —
// this probe is just "is the cloud reachable?", not a security
// boundary; libscadable establishes the actual mTLS session later.
static bool ping_cloud_health(void)
{
    ESP_LOGI(TAG, "Probing cloud health: %s", CONFIG_SCADABLE_OTA_HEALTH_URL);

    esp_http_client_config_t http_cfg = {
        .url = CONFIG_SCADABLE_OTA_HEALTH_URL,
        .timeout_ms = 5000,
        .crt_bundle_attach = NULL,  // use system bundle if available
        .skip_cert_common_name_check = false,
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
    };
    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    if (!client) {
        ESP_LOGW(TAG, "HTTP client init failed");
        return false;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status = -1;
    if (err == ESP_OK) {
        status = esp_http_client_get_status_code(client);
    } else {
        ESP_LOGW(TAG, "HTTP request failed: %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);

    if (status == 200) {
        ESP_LOGI(TAG, "Cloud health: 200 OK");
        return true;
    }
    ESP_LOGW(TAG, "Cloud health probe failed (status=%d)", status);
    return false;
}

provisioning_mode_t decide_mode(void)
{
    // ---- Step 1: WiFi creds in NVS? ----
    char ssid[33] = {0};
    char password[65] = {0};
    if (!read_wifi_creds(ssid, sizeof(ssid), password, sizeof(password))) {
        ESP_LOGI(TAG, "Decision: no saved WiFi creds → AP mode");
        boot_state_set_reason(BOOT_REASON_WIFI_CREDS_MISSING);
        return MODE_AP;
    }

    // ---- Step 2: device cert in NVS? ----
    if (!nvs_key_present(NVS_NAMESPACE_CERTS, NVS_KEY_DEVICE_CERT) ||
        !nvs_key_present(NVS_NAMESPACE_CERTS, NVS_KEY_DEVICE_KEY)) {
        // This means the chip wasn't properly flashed — either
        // somebody loaded the provisioning firmware via `idf.py
        // flash` without going through the SCADABLE web flasher
        // (which mints + writes the cert), or the cert was wiped.
        // We still go to AP mode rather than halting, so the
        // serial/captive-portal banner can tell the customer to
        // re-flash.
        ESP_LOGE(TAG,
                 "Decision: NVS namespace `scadable_certs` missing — chip needs "
                 "to be flashed via the SCADABLE dashboard. Falling back to AP "
                 "mode so you can see this message in the captive portal.");
        boot_state_set_reason(BOOT_REASON_NVS_CERTS_MISSING);
        return MODE_AP;
    }

    // ---- Step 3: can we actually connect? ----
    if (!try_connect_saved_wifi(ssid, password)) {
        ESP_LOGI(TAG, "Decision: saved WiFi unreachable → AP mode");
        // Translate the persisted wifi attempt outcome into the
        // matching reason enum so the captive portal banner shows the
        // specific failure (auth_failed vs no_ap_found vs timeout)
        // instead of a generic "couldn't connect".
        switch (s_last_disconnect_reason) {
            case WIFI_REASON_NO_AP_FOUND:
                boot_state_set_reason(BOOT_REASON_WIFI_NO_AP_FOUND);
                break;
            case WIFI_REASON_AUTH_FAIL:
            case WIFI_REASON_HANDSHAKE_TIMEOUT:
            case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
            case WIFI_REASON_MIC_FAILURE:
                boot_state_set_reason(BOOT_REASON_WIFI_AUTH_FAILED);
                break;
            case WIFI_REASON_BEACON_TIMEOUT:
            case WIFI_REASON_ASSOC_EXPIRE:
                boot_state_set_reason(BOOT_REASON_WIFI_TIMEOUT);
                break;
            case 0:
                // No disconnect event at all → timeout waiting for IP.
                boot_state_set_reason(BOOT_REASON_WIFI_TIMEOUT);
                break;
            default:
                boot_state_set_reason(BOOT_REASON_WIFI_CONNECT_FAILED);
                break;
        }
        return MODE_AP;
    }

    // ---- Step 4: cloud reachable? ----
    if (!ping_cloud_health()) {
        ESP_LOGI(TAG, "Decision: WiFi up but cloud unreachable → AP mode "
                      "(maybe captive-portal'd network or DNS broken)");
        boot_state_set_reason(BOOT_REASON_CLOUD_UNREACHABLE);
        // Tear down WiFi + STA netif so ap_provisioning_start can re-init.
        // (Without destroying the default STA netif here too, the assert
        // at wifi_default.c:388 would fire when AP mode brings APSTA up.)
        teardown_sta_for_ap_mode();
        return MODE_AP;
    }

    ESP_LOGI(TAG, "Decision: all checks passed → OTA pull mode");
    boot_state_set_reason(BOOT_REASON_NONE);
    return MODE_OTA_PULL;
}
