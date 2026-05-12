// boot_state.c — single-writer process-wide diagnostic state.
// SCADABLE 2026 · Apache-2.0
//
// See boot_state.h for the design rationale. This file is intentionally
// boring: a static struct, a small NVS-backed counter, and JSON
// rendering. No threading primitives — the writers are all on the
// startup path before any other task is reading, and the HTTP /state
// handler reads best-effort.

#include "boot_state.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "sdkconfig.h"

static const char *TAG = "scadable.boot_state";

// Dedicated NVS namespace for boot diagnostics. Distinct from `wifi`
// (provisioning creds) and `scadable_certs` (libscadable cert) so
// wiping one doesn't lose the others.
#define NVS_NAMESPACE_META       "scadable_meta"
#define NVS_KEY_BOOT_COUNT       "boot_count"
#define NVS_KEY_LAST_SEEN_SSID   "last_ssid"
#define NVS_KEY_WIFI_ATTEMPT     "wifi_attempt"

// Stored process-wide. Single instance per boot. Initialized to "no
// data yet" so the /state handler always returns something coherent
// even if it's hit before boot_state_init() runs.
static struct {
    boot_decision_t decision;
    boot_reason_t reason;
    boot_wifi_attempt_t wifi_attempt;
    uint32_t boot_count;
    char last_seen_ssid[33];   // 32 + NUL — matches wifi_config_t.ssid
    int64_t boot_start_us;     // captured in boot_state_init()
} s_state = {
    .decision = BOOT_DECISION_UNKNOWN,
    .reason = BOOT_REASON_NONE,
    .wifi_attempt = BOOT_WIFI_ATTEMPT_NONE,
    .boot_count = 0,
    .last_seen_ssid = {0},
    .boot_start_us = 0,
};

// ─── enum → string helpers ─────────────────────────────────────────

const char *boot_state_decision_to_string(boot_decision_t d)
{
    switch (d) {
        case BOOT_DECISION_AP_MODE:  return "ap_mode";
        case BOOT_DECISION_OTA_PULL: return "ota_pull";
        case BOOT_DECISION_UNKNOWN:
        default:                     return "unknown";
    }
}

const char *boot_state_reason_to_string(boot_reason_t r)
{
    switch (r) {
        case BOOT_REASON_NONE:                return "none";
        case BOOT_REASON_WIFI_CREDS_MISSING:  return "wifi_creds_missing";
        case BOOT_REASON_NVS_CERTS_MISSING:   return "nvs_certs_missing";
        case BOOT_REASON_WIFI_CONNECT_FAILED: return "wifi_connect_failed";
        case BOOT_REASON_WIFI_AUTH_FAILED:    return "wifi_auth_failed";
        case BOOT_REASON_WIFI_NO_AP_FOUND:    return "wifi_no_ap_found";
        case BOOT_REASON_WIFI_TIMEOUT:        return "wifi_timeout";
        case BOOT_REASON_CLOUD_UNREACHABLE:   return "cloud_unreachable";
        case BOOT_REASON_CLOUD_UNAUTHORIZED:  return "cloud_unauthorized";
        case BOOT_REASON_CLOUD_TIMEOUT:       return "cloud_timeout";
        case BOOT_REASON_UNKNOWN:
        default:                              return "unknown";
    }
}

// Human strings the captive portal renders verbatim. Tone is
// "tell the operator what's actually wrong + what they can do about it"
// — these are the messages that replace an hour of bench debugging.
const char *boot_state_reason_to_human(boot_reason_t r)
{
    switch (r) {
        case BOOT_REASON_NONE:
            return "Device is healthy.";
        case BOOT_REASON_WIFI_CREDS_MISSING:
            return "No WiFi credentials saved yet — pick a network below.";
        case BOOT_REASON_NVS_CERTS_MISSING:
            return "NVS namespace 'scadable_certs' is missing — chip needs to be "
                   "flashed via the SCADABLE dashboard.";
        case BOOT_REASON_WIFI_CONNECT_FAILED:
            return "Saved WiFi network couldn't be joined. Try a different network "
                   "or double-check the password.";
        case BOOT_REASON_WIFI_AUTH_FAILED:
            return "WiFi password was rejected. Re-enter it below.";
        case BOOT_REASON_WIFI_NO_AP_FOUND:
            return "Saved WiFi network isn't visible from this location. Pick a "
                   "different network or move the device closer to the router.";
        case BOOT_REASON_WIFI_TIMEOUT:
            return "WiFi connect timed out. The network may be unstable — try again "
                   "or pick a different one.";
        case BOOT_REASON_CLOUD_UNREACHABLE:
            return "WiFi joined but the SCADABLE cloud is unreachable. The network "
                   "may be a captive-portal hotspot, or DNS is blocked.";
        case BOOT_REASON_CLOUD_UNAUTHORIZED:
            return "Cloud reached but rejected this device. The certificate may be "
                   "revoked — re-flash via the SCADABLE dashboard.";
        case BOOT_REASON_CLOUD_TIMEOUT:
            return "Cloud probe timed out. Network is slow or the SCADABLE control "
                   "plane is degraded.";
        case BOOT_REASON_UNKNOWN:
        default:
            return "Device is in setup mode for an unknown reason. Check the serial "
                   "log for details.";
    }
}

const char *boot_state_wifi_attempt_to_string(boot_wifi_attempt_t a)
{
    switch (a) {
        case BOOT_WIFI_ATTEMPT_NONE:        return "none";
        case BOOT_WIFI_ATTEMPT_SUCCESS:     return "success";
        case BOOT_WIFI_ATTEMPT_AUTH_FAILED: return "auth_failed";
        case BOOT_WIFI_ATTEMPT_NO_AP_FOUND: return "no_ap_found";
        case BOOT_WIFI_ATTEMPT_TIMEOUT:     return "timeout";
        case BOOT_WIFI_ATTEMPT_OTHER:
        default:                            return "other";
    }
}

// ─── NVS persistence ───────────────────────────────────────────────

static void load_persisted_fields(void)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE_META, NVS_READWRITE, &handle) != ESP_OK) {
        ESP_LOGW(TAG, "could not open meta NVS — first boot or NVS broken");
        return;
    }

    // boot_count: increment in-place. Missing key → start at 1.
    uint32_t count = 0;
    esp_err_t err = nvs_get_u32(handle, NVS_KEY_BOOT_COUNT, &count);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "boot_count read failed: %s", esp_err_to_name(err));
    }
    count += 1;
    if (nvs_set_u32(handle, NVS_KEY_BOOT_COUNT, count) != ESP_OK) {
        ESP_LOGW(TAG, "boot_count write failed");
    }
    s_state.boot_count = count;

    // last_seen_ssid: optional. Empty string if never set.
    size_t len = sizeof(s_state.last_seen_ssid);
    err = nvs_get_str(handle, NVS_KEY_LAST_SEEN_SSID, s_state.last_seen_ssid, &len);
    if (err != ESP_OK) {
        s_state.last_seen_ssid[0] = '\0';
    }

    // wifi_attempt: stored as a small string (matches the JSON form
    // we serve, so the operator sees the same token in both places).
    char attempt_str[16] = {0};
    len = sizeof(attempt_str);
    err = nvs_get_str(handle, NVS_KEY_WIFI_ATTEMPT, attempt_str, &len);
    if (err == ESP_OK) {
        if      (strcmp(attempt_str, "success")     == 0) s_state.wifi_attempt = BOOT_WIFI_ATTEMPT_SUCCESS;
        else if (strcmp(attempt_str, "auth_failed") == 0) s_state.wifi_attempt = BOOT_WIFI_ATTEMPT_AUTH_FAILED;
        else if (strcmp(attempt_str, "no_ap_found") == 0) s_state.wifi_attempt = BOOT_WIFI_ATTEMPT_NO_AP_FOUND;
        else if (strcmp(attempt_str, "timeout")     == 0) s_state.wifi_attempt = BOOT_WIFI_ATTEMPT_TIMEOUT;
        else if (strcmp(attempt_str, "other")       == 0) s_state.wifi_attempt = BOOT_WIFI_ATTEMPT_OTHER;
        else                                              s_state.wifi_attempt = BOOT_WIFI_ATTEMPT_NONE;
    }

    nvs_commit(handle);
    nvs_close(handle);
}

void boot_state_init(void)
{
    s_state.boot_start_us = esp_timer_get_time();
    load_persisted_fields();
    ESP_LOGI(TAG, "boot_state initialized: boot_count=%" PRIu32
                  " last_seen_ssid='%s' wifi_attempt=%s",
             s_state.boot_count, s_state.last_seen_ssid,
             boot_state_wifi_attempt_to_string(s_state.wifi_attempt));
}

// ─── Setters ───────────────────────────────────────────────────────

void boot_state_set_decision(boot_decision_t d)
{
    s_state.decision = d;
}

void boot_state_set_reason(boot_reason_t r)
{
    s_state.reason = r;
}

void boot_state_record_wifi_attempt(boot_wifi_attempt_t result, const char *ssid)
{
    s_state.wifi_attempt = result;

    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE_META, NVS_READWRITE, &handle) != ESP_OK) {
        ESP_LOGW(TAG, "wifi_attempt NVS open failed — not persisting");
        return;
    }
    nvs_set_str(handle, NVS_KEY_WIFI_ATTEMPT,
                boot_state_wifi_attempt_to_string(result));

    // Only update last_seen_ssid on success — we don't want to remember
    // a failed-auth SSID as "last good" because the next boot would
    // mislead the operator into thinking a known-bad network worked.
    if (result == BOOT_WIFI_ATTEMPT_SUCCESS && ssid && ssid[0]) {
        nvs_set_str(handle, NVS_KEY_LAST_SEEN_SSID, ssid);
        strncpy(s_state.last_seen_ssid, ssid, sizeof(s_state.last_seen_ssid) - 1);
        s_state.last_seen_ssid[sizeof(s_state.last_seen_ssid) - 1] = '\0';
    }

    nvs_commit(handle);
    nvs_close(handle);
}

void boot_state_clear_persisted_wifi_attempt(void)
{
    nvs_handle_t handle;
    if (nvs_open(NVS_NAMESPACE_META, NVS_READWRITE, &handle) != ESP_OK) {
        return;
    }
    nvs_erase_key(handle, NVS_KEY_WIFI_ATTEMPT);
    nvs_commit(handle);
    nvs_close(handle);
    s_state.wifi_attempt = BOOT_WIFI_ATTEMPT_NONE;
}

// ─── JSON renderer ─────────────────────────────────────────────────

// Escape a JSON string into `out`, writing at most cap-1 chars and
// NUL-terminating. We only need to handle the small set of chars that
// can appear in an SSID — quotes, backslashes, and control bytes —
// since everything else in the payload is enum-derived.
static void json_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    if (cap == 0) return;
    for (size_t i = 0; in && in[i] && o + 2 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            if (o + 3 >= cap) break;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            // Drop control chars rather than emitting \uXXXX — keeps
            // this routine tiny and SSIDs don't legitimately contain
            // control bytes.
            continue;
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

int boot_state_render_json(char *out, size_t cap)
{
    if (!out || cap < 64) return -1;

    // Snapshot to local vars in case a writer races us. The struct is
    // tiny enough that field-by-field copies are essentially free.
    boot_decision_t decision     = s_state.decision;
    boot_reason_t   reason       = s_state.reason;
    boot_wifi_attempt_t attempt  = s_state.wifi_attempt;
    uint32_t boot_count          = s_state.boot_count;
    int64_t now_us               = esp_timer_get_time();
    uint32_t uptime_secs         = (uint32_t)((now_us - s_state.boot_start_us) / 1000000);

    char ssid_escaped[2 * sizeof(s_state.last_seen_ssid) + 1] = {0};
    json_escape(s_state.last_seen_ssid, ssid_escaped, sizeof(ssid_escaped));

    // Human reason can contain apostrophes — they're fine inside JSON
    // strings (no escaping required). Static lookup never contains
    // double quotes or backslashes; if a future entry does, swap to
    // json_escape() here too.
    const char *human = boot_state_reason_to_human(reason);

    int n;
    if (ssid_escaped[0]) {
        n = snprintf(out, cap,
            "{"
            "\"decision\":\"%s\","
            "\"reason\":\"%s\","
            "\"reason_human\":\"%s\","
            "\"boot_count\":%" PRIu32 ","
            "\"last_seen_ssid\":\"%s\","
            "\"wifi_attempt\":\"%s\","
            "\"uptime_secs\":%" PRIu32 ","
            "\"firmware_version\":\"%s\""
            "}",
            boot_state_decision_to_string(decision),
            boot_state_reason_to_string(reason),
            human,
            boot_count,
            ssid_escaped,
            boot_state_wifi_attempt_to_string(attempt),
            uptime_secs,
            CONFIG_SCADABLE_FIRMWARE_VERSION);
    } else {
        // No last_seen_ssid → emit JSON null instead of an empty
        // string. Operator-facing JS branches on null to suppress the
        // "Last SSID:" row entirely.
        n = snprintf(out, cap,
            "{"
            "\"decision\":\"%s\","
            "\"reason\":\"%s\","
            "\"reason_human\":\"%s\","
            "\"boot_count\":%" PRIu32 ","
            "\"last_seen_ssid\":null,"
            "\"wifi_attempt\":\"%s\","
            "\"uptime_secs\":%" PRIu32 ","
            "\"firmware_version\":\"%s\""
            "}",
            boot_state_decision_to_string(decision),
            boot_state_reason_to_string(reason),
            human,
            boot_count,
            boot_state_wifi_attempt_to_string(attempt),
            uptime_secs,
            CONFIG_SCADABLE_FIRMWARE_VERSION);
    }

    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}
