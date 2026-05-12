# gateway-provisioning main component.
# SCADABLE 2026 · Apache-2.0

idf_component_register(
    SRCS
        "main.c"
        "boot_decision.c"
        "boot_state.c"
        "ap_provisioning.c"
        "cloud_check.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        esp_http_server
        esp_http_client
        esp-tls
        esp_timer
        driver
        json
        lwip
        mdns
)
