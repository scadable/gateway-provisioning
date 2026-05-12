// branding.c — load per-org captive-portal branding from NVS.
// SCADABLE 2026 · Apache-2.0
//
// See branding.h for the design rationale. Every field independently
// falls back to its compile-time default, so an un-branded chip and a
// partially-branded chip both produce well-formed HTML.

#include "branding.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

static const char *TAG = "scadable.brand";

#define NVS_NAMESPACE_BRAND "scadable_brand"
#define NVS_KEY_TITLE       "title"
#define NVS_KEY_BODY        "body"
#define NVS_KEY_SSID        "ssid"
#define NVS_KEY_COLOR       "color"
#define NVS_KEY_LOGO        "logo"

// load_str reads a string key into `out`/`cap` if present and
// non-empty. Returns true if a non-empty value landed; false if the
// key is missing, empty, or unreadable (caller should keep the
// pre-populated default).
static bool load_str(nvs_handle_t handle, const char *key, char *out, size_t cap)
{
    size_t len = cap;
    esp_err_t err = nvs_get_str(handle, key, out, &len);
    if (err != ESP_OK) {
        // Most common: ESP_ERR_NVS_NOT_FOUND. Anything else is also
        // soft-failed — we don't want a flaky NVS to brick the
        // captive portal.
        return false;
    }
    // nvs_get_str writes a NUL-terminated string; len is total size
    // including the NUL. An empty value (len <= 1) → leave default.
    if (len <= 1 || out[0] == '\0') {
        return false;
    }
    // Belt-and-suspenders: NUL-terminate at cap-1 in case a future
    // NVS write somehow stored an unterminated buffer.
    out[cap - 1] = '\0';
    return true;
}

void branding_load(branding_t *out)
{
    if (!out) return;

    // Pre-populate compile-time defaults. Every field independently
    // overridable below.
    snprintf(out->title, sizeof(out->title), "%s setup", CONFIG_SCADABLE_COMPANY_NAME);
    out->body[0] = '\0';
    snprintf(out->ssid_prefix, sizeof(out->ssid_prefix), "%s-Setup", CONFIG_SCADABLE_COMPANY_NAME);
    snprintf(out->accent_color, sizeof(out->accent_color), "#F56300");
    out->logo_url[0] = '\0';

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE_BRAND, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        // Steady state for un-branded firmware — namespace doesn't
        // exist yet because the dashboard never wrote any keys for
        // this device. Not a warning.
        ESP_LOGI(TAG, "no scadable_brand namespace in NVS — using compile-time defaults");
        return;
    }

    bool any = false;
    if (load_str(handle, NVS_KEY_TITLE,  out->title,        sizeof(out->title)))        any = true;
    if (load_str(handle, NVS_KEY_BODY,   out->body,         sizeof(out->body)))         any = true;
    if (load_str(handle, NVS_KEY_SSID,   out->ssid_prefix,  sizeof(out->ssid_prefix)))  any = true;
    if (load_str(handle, NVS_KEY_COLOR,  out->accent_color, sizeof(out->accent_color))) any = true;
    if (load_str(handle, NVS_KEY_LOGO,   out->logo_url,     sizeof(out->logo_url)))     any = true;

    nvs_close(handle);

    if (any) {
        ESP_LOGI(TAG, "loaded org branding from NVS (title='%s', ssid='%s', accent='%s', logo='%s')",
                 out->title, out->ssid_prefix, out->accent_color,
                 out->logo_url[0] ? "set" : "(none)");
    } else {
        ESP_LOGI(TAG, "scadable_brand namespace empty — using compile-time defaults");
    }
}
