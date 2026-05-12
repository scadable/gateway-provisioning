// boot_state.h — process-wide diagnostic state captured during the
// boot decision flow and surfaced to the captive portal via /state.
// SCADABLE 2026 · Apache-2.0
//
// Why this exists: when boot_decision falls back to AP mode the
// captive portal has historically had no idea WHY. The end-user sees
// a generic "connect WiFi" page even when the underlying problem is
// "scadable_certs missing" or "cloud unreachable" — which sends them
// in circles entering correct WiFi creds while the chip can't proceed
// for unrelated reasons.
//
// boot_state collects:
//   - the decision outcome (AP / OTA pull) and a structured reason
//     for why we ended up there
//   - persistent counters / last-known-good fields (boot_count,
//     last_seen_ssid, wifi_attempt) that survive reboot via NVS
//     namespace `scadable_meta`
//   - uptime + firmware_version for operator-side debugging
//
// Everything here is single-writer (boot_decision.c + main.c during
// startup, ap_provisioning.c on a successful POST /connect). The
// reader (HTTP /state handler) is best-effort — it tolerates a torn
// read by serving whatever is currently in the struct. We don't bother
// with a mutex; the values are tiny and an occasional stale field is
// strictly better than a missing /state response.

#ifndef GATEWAY_PROVISIONING_BOOT_STATE_H
#define GATEWAY_PROVISIONING_BOOT_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Decision outcome — mirrors provisioning_mode_t but is its own enum
 * so boot_state.h doesn't have to pull in boot_decision.h (and to
 * leave room for future "halted" / "recovery" states without churning
 * the boot decision API).
 */
typedef enum {
    BOOT_DECISION_UNKNOWN = 0,
    BOOT_DECISION_AP_MODE = 1,
    BOOT_DECISION_OTA_PULL = 2,
} boot_decision_t;

/**
 * Why we ended up where we did. The string form is what the captive
 * portal renders; keep it short, lowercase, snake_case (the JS
 * branches on it for icon selection).
 *
 * Add new values at the bottom — boot_state_reason_to_string() does a
 * straightforward switch and the captive portal JS treats unknown
 * values as "show generic warning".
 */
typedef enum {
    BOOT_REASON_NONE = 0,                  // OTA-pull path, nothing to report
    BOOT_REASON_WIFI_CREDS_MISSING,        // first boot; expected
    BOOT_REASON_NVS_CERTS_MISSING,         // chip wasn't flashed via the dashboard
    BOOT_REASON_WIFI_CONNECT_FAILED,       // generic connect failure (no specific code)
    BOOT_REASON_WIFI_AUTH_FAILED,          // bad password
    BOOT_REASON_WIFI_NO_AP_FOUND,          // SSID not visible
    BOOT_REASON_WIFI_TIMEOUT,              // didn't get IP within timeout
    BOOT_REASON_CLOUD_UNREACHABLE,         // WiFi up but cloud probe failed
    BOOT_REASON_CLOUD_UNAUTHORIZED,        // cloud reached but rejected (4xx)
    BOOT_REASON_CLOUD_TIMEOUT,             // cloud probe timed out
    BOOT_REASON_UNKNOWN,
} boot_reason_t;

/**
 * Result of the most recent WiFi connect attempt. Persisted to NVS
 * across reboots so the captive portal can show "your last attempt
 * failed because…" on the boot AFTER the user submitted creds.
 *
 * BOOT_WIFI_ATTEMPT_NONE means "no attempt has been made yet on this
 * chip" — common-case first boot.
 */
typedef enum {
    BOOT_WIFI_ATTEMPT_NONE = 0,
    BOOT_WIFI_ATTEMPT_SUCCESS,
    BOOT_WIFI_ATTEMPT_AUTH_FAILED,
    BOOT_WIFI_ATTEMPT_NO_AP_FOUND,
    BOOT_WIFI_ATTEMPT_TIMEOUT,
    BOOT_WIFI_ATTEMPT_OTHER,
} boot_wifi_attempt_t;

/**
 * Initialize boot_state at app_main() start. Reads boot_count,
 * last_seen_ssid, and wifi_attempt from NVS; increments boot_count
 * and writes it back. Safe to call after nvs_flash_init().
 *
 * Must be called BEFORE decide_mode() so the state struct is
 * populated by the time the /state handler can be hit.
 */
void boot_state_init(void);

/**
 * Setters used by boot_decision.c and main.c during startup.
 * boot_state_set_decision() is the only one called by main.c after
 * decide_mode() returns; the rest are called from inside the boot
 * decision flow as it walks the checklist.
 */
void boot_state_set_decision(boot_decision_t d);
void boot_state_set_reason(boot_reason_t r);

/**
 * Record the WiFi attempt outcome. Persists to NVS so the next boot
 * can show the operator what went wrong on the previous attempt.
 * `ssid` is only persisted on the SUCCESS path (last_seen_ssid).
 */
void boot_state_record_wifi_attempt(boot_wifi_attempt_t result, const char *ssid);

/**
 * Clear the persisted wifi_attempt field. Called from POST /connect
 * after we save fresh creds so the next boot starts from a clean
 * "no attempt yet" state instead of inheriting the previous failure.
 */
void boot_state_clear_persisted_wifi_attempt(void);

/**
 * Render the current boot_state into a JSON object suitable for the
 * captive portal's GET /state endpoint. Writes at most `cap` bytes
 * (including the trailing NUL) to `out` and returns the number of
 * bytes written, or -1 on error.
 *
 * The output is stable across calls within a single boot — the
 * captive portal polls this every 5s and the operator copies it via
 * the "Copy details" button.
 */
int boot_state_render_json(char *out, size_t cap);

/**
 * String forms — used for both JSON serialization and the human
 * lookup table in boot_state_reason_to_human(). Always returns a
 * non-NULL static string; never owns memory.
 */
const char *boot_state_decision_to_string(boot_decision_t d);
const char *boot_state_reason_to_string(boot_reason_t r);
const char *boot_state_reason_to_human(boot_reason_t r);
const char *boot_state_wifi_attempt_to_string(boot_wifi_attempt_t a);

#ifdef __cplusplus
}
#endif

#endif  // GATEWAY_PROVISIONING_BOOT_STATE_H
