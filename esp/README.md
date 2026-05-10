# esp/ — ESP-IDF provisioning firmware

This is the firmware that lives in the `factory` partition of every
SCADABLE-managed ESP32. See the repo-root `README.md` for the boot
flow story; this file is the build/development reference.

## Boot flow (where to read first)

```
app_main (main.c)
  ├─ check GPIO0 held → wipe `wifi` NVS namespace
  ├─ decide_mode (boot_decision.c)
  │    ├─ NVS `wifi.{ssid,password}` missing? → MODE_AP
  │    ├─ NVS `scadable_certs.{device_cert,device_key}` missing? → MODE_AP
  │    ├─ try connect to saved WiFi (30s timeout) → fail = MODE_AP
  │    └─ HTTPS GET CONFIG_SCADABLE_OTA_HEALTH_URL → 200 = MODE_OTA_PULL
  │
  ├─ MODE_AP        → ap_provisioning_start (ap_provisioning.c)
  │                     SoftAP + DNS sinkhole + captive HTTP server
  │                     POST /connect → write NVS → reboot
  │
  └─ MODE_OTA_PULL  → cloud_check_run (cloud_check.c)
                        scadable_init / scadable_connect
                        publish {"state":"provisioned",...}
                        idle while libscadable applies OTA
                        OTA reboot into ota_0/ota_1 = customer fw
```

## Files

| File                   | Role |
|------------------------|------|
| `main/main.c`          | `app_main`, recovery hook, mode dispatch |
| `main/boot_decision.*` | Read NVS, attempt WiFi+health probe, return enum |
| `main/ap_provisioning.*` | SoftAP, captive DNS, HTTP form, NVS writeback |
| `main/cloud_check.*`   | libscadable lifecycle, one-shot provisioned status |
| `main/idf_component.yml` | `crypto-a/libscadable: ^0.1.0`, `espressif/wifi_provisioning` |
| `partitions.csv`       | `factory + ota_0 + ota_1 + nvs + phy_init` |
| `sdkconfig.defaults`   | IDF tunables (HTTP server, OTA rollback, custom partition table) |
| `Kconfig.projbuild`    | `CONFIG_SCADABLE_COMPANY_NAME`, `CONFIG_SCADABLE_OTA_HEALTH_URL` |

## Build

```bash
. $IDF_PATH/export.sh             # ESP-IDF v5.1+
idf.py set-target esp32           # or esp32s3
idf.py build
idf.py -p /dev/cu.usbserial-XXXX flash monitor
```

## Customizing the brand

```bash
idf.py menuconfig
# → Component config → SCADABLE provisioning
#     Company name (shown in AP SSID + setup page) [SCADABLE]
#     Cloud health endpoint for connectivity check  [https://edge.scadable.com/health]
```

Or pass via env in CI:

```bash
echo "CONFIG_SCADABLE_COMPANY_NAME=\"Verdant\"" > sdkconfig.brand
echo "CONFIG_SCADABLE_OTA_HEALTH_URL=\"https://edge.verdant.example/health\"" >> sdkconfig.brand
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.brand" idf.py build
```

## Why a captive portal (and not the upstream `wifi_provisioning`)?

The upstream `espressif/wifi_provisioning` component is excellent for
phone-app pairing flows (BLE Provisioner, ESP SoftAP Prov, etc.) —
it ships an encrypted security-1 channel and is the right answer for
Phase 2.

But our v1 use case is a customer who plugs in a chip and wants a
captive portal to pop in their browser within seconds, no app
install required. So v1 implements the captive portal directly
(DNS sinkhole + form POST → NVS write → reboot) and intentionally
skips the encrypted channel — the AP only exists for ~60 seconds
during initial site setup, the password never leaves the local
network, and Ali confirmed this risk profile is acceptable for v1.

To keep Phase 2 cheap, the v1 captive portal writes to the *same*
NVS layout the upstream `wifi_provisioning` component uses
(namespace `wifi`, keys `ssid` + `password`). That means already-
provisioned chips keep working when we swap the UX. See
`main/idf_component.yml` for the explanatory note on the dep.
