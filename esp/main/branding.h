// branding.h — per-org captive-portal branding loaded from NVS.
//
// SCADABLE 2026 · Apache-2.0
//
// At flash time, dashboard.scadable.com's BYOR flasher writes the
// customer's saved branding into NVS namespace `scadable_brand`
// (alongside the existing `scadable_certs` and `scadable_cfg`
// namespaces). This module reads those values at portal-render time,
// falling back to compile-time Kconfig defaults for any missing key.
//
// Why a struct + load function rather than per-key getters: the
// captive-portal HTML render path needs all four string substitutions
// in one snprintf call; bundling them up means one NVS round-trip
// instead of five. Lifetime is "until ap_provisioning_start exits"
// (which is "forever" in v1) — caller doesn't free.
//
// Buffer ownership: `branding_t` owns small char buffers sized to the
// known maxima the dashboard form enforces (title 100, body 2000,
// SSID prefix 24, accent color 16, logo URL 500). The dashboard
// caps the input lengths so no NVS read can overflow these — but
// branding_load() also defends in depth by truncating on read.

#ifndef GATEWAY_PROVISIONING_BRANDING_H
#define GATEWAY_PROVISIONING_BRANDING_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hard buffer caps. Match the dashboard form maxLengths + 1 for NUL.
// Bumping any of these requires bumping the dashboard input cap in
// lockstep so the chip-side defence isn't unnecessarily tighter than
// the cloud-side input limit.
#define BRANDING_TITLE_MAX  101  // dashboard: 100
#define BRANDING_BODY_MAX  2001  // dashboard: 2000
#define BRANDING_SSID_MAX    25  // dashboard: 24
#define BRANDING_COLOR_MAX   17  // dashboard: 16
#define BRANDING_LOGO_MAX   501  // dashboard: 500

typedef struct {
    char title[BRANDING_TITLE_MAX];
    char body[BRANDING_BODY_MAX];
    char ssid_prefix[BRANDING_SSID_MAX];
    char accent_color[BRANDING_COLOR_MAX];
    char logo_url[BRANDING_LOGO_MAX];
} branding_t;

/**
 * Populate `out` from NVS namespace `scadable_brand`. Each field
 * falls back to its compile-time default if the NVS key is missing,
 * empty, or truncated. Always succeeds (returns void) — a missing
 * NVS namespace is the steady state for un-branded builds and is
 * not a failure mode.
 *
 * Compile-time defaults:
 *   - title         : "<COMPANY> setup"
 *   - body          : "" (empty — caller renders the canonical default copy)
 *   - ssid_prefix   : CONFIG_SCADABLE_COMPANY_NAME "-Setup"
 *   - accent_color  : "#F56300" (matches firmware --orange CTA)
 *   - logo_url      : ""
 */
void branding_load(branding_t *out);

#ifdef __cplusplus
}
#endif

#endif  // GATEWAY_PROVISIONING_BRANDING_H
