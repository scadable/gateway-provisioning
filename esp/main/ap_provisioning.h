// ap_provisioning.h — SoftAP + captive portal for first-boot WiFi
// onboarding.
//
// SCADABLE 2026 · Apache-2.0

#ifndef GATEWAY_PROVISIONING_AP_PROVISIONING_H
#define GATEWAY_PROVISIONING_AP_PROVISIONING_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bring up the SoftAP and captive portal. Blocks forever (or until
 * CONFIG_SCADABLE_AP_TIMEOUT_SECS expires, if non-zero) — the only
 * way out is the customer submitting valid creds, which writes NVS
 * and reboots the chip from inside the HTTP handler.
 *
 * SSID format: "{PREFIX}-{6-char-uppercase-hex-MAC}"
 *   e.g. "SCADABLE-Setup-A4F3B2" (default prefix), or "Acme-Setup-A4F3B2"
 *   when the org has set branding.ssid_prefix = "Acme-Setup" via the
 *   dashboard's Branding tab. See branding.h.
 *
 * IP: 192.168.4.1 (IDF default for SoftAP). DNS sinkhole points all
 * lookups at that address so any browser request triggers the OS's
 * captive-portal popup.
 *
 * Brings up:
 *   - WiFi in APSTA mode (AP for the customer + STA for the
 *     credential test)
 *   - DHCP server (built into IDF's esp_netif default AP config)
 *   - DNS sinkhole on UDP/53
 *   - HTTP server on TCP/80 serving the setup form + /scan + /connect
 *     endpoints
 *   - mDNS responder for `scadable-setup.local`
 */
void ap_provisioning_start(void);

#ifdef __cplusplus
}
#endif

#endif  // GATEWAY_PROVISIONING_AP_PROVISIONING_H
