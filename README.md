# gateway-provisioning

Recovery firmware that ships pre-flashed onto every SCADABLE-managed
ESP32 chip. Customers never write this code — they receive a chip that
already has it installed (either flashed at the factory or by the
SCADABLE dashboard's "Add Device → Provisioning mode" path).

## What it does

When a customer plugs the chip in at their site for the first time:

1. The chip boots into **AP mode** with a SoftAP named
   `SCADABLE-Setup-XXXXXX` (the `XXXXXX` is the last 6 hex digits of
   the device MAC, so multiple devices on one site don't collide).
2. The customer's phone or laptop connects to that AP. A **captive
   portal** auto-pops a setup page: "pick a WiFi network, enter the
   password, hit Connect."
3. The chip writes the WiFi creds to NVS, reboots, joins the chosen
   network, and reaches the SCADABLE cloud using the **device cert
   that was minted at flash time** (stored in NVS namespace
   `scadable_certs`).
4. As soon as MQTT comes up the chip publishes a one-shot
   `state=provisioned` status. The dashboard now sees the device as
   "provisioned, awaiting customer firmware."
5. The cloud's existing `release.apply` flow pushes the **customer's
   real firmware** as an OTA. libscadable's OTA hook validates the
   image, swaps OTA partitions, and reboots into it. This provisioning
   firmware then sleeps in the `factory` slot as a recovery target
   forever.

If anything goes wrong on a later boot — bad WiFi creds after a router
swap, OTA image fails to validate, customer firmware panics enough to
trigger rollback — the bootloader falls back to this `factory` slot
and we're back at step 1, captive portal up, customer can re-onboard.

## Recovery hook

Hold **GPIO0** (the BOOT button) low for 5 seconds at boot to wipe the
saved WiFi creds. Useful when a device moves between sites or the
customer changes routers.

## White-label

Two `Kconfig.projbuild` knobs cover the brand surfaces:

- `CONFIG_SCADABLE_COMPANY_NAME` — defaults to `"SCADABLE"`. Used in
  the AP SSID, captive portal page title, and serial banner.
- `CONFIG_SCADABLE_OTA_HEALTH_URL` — defaults to
  `"https://edge.scadable.com/health"`. White-label deployments point
  this at their own cloud.

## Build

ESP-IDF v5.1 or newer. From `esp/`:

```bash
idf.py set-target esp32          # or esp32s3
idf.py menuconfig                # set Kconfig if customizing
idf.py build
idf.py -p /dev/cu.usbserial-... flash monitor
```

CI in `.github/workflows/build.yml` builds for `esp32` and `esp32s3`
on every push and PR; tagged commits also publish the binary as a
GitHub release artifact.

## Phase 2

- **BLE provisioning.** `wifi_provisioning` lib already supports
  `prov_scheme_ble`; the captive-portal layer in `ap_provisioning.c`
  becomes optional once the dashboard has a cross-platform BLE
  pairing flow.
- **Linux provisioning.** The headless equivalent for `gateway-linux`
  installs lives under `linux/` (placeholder today). Same boot
  decision, same NVS-backed cert, but the user-facing surface is a
  systemd service + `nmcli` instead of a SoftAP.

## Repo layout

```
esp/                              ESP-IDF project
  main/
    main.c                        boot decision + state machine
    boot_decision.{h,c}           "AP or OTA-pull?"
    ap_provisioning.{h,c}         SoftAP + DNS + captive portal
    cloud_check.{h,c}             libscadable lifecycle + status publish
    idf_component.yml             libscadable + wifi_provisioning deps
  partitions.csv                  factory + ota_0 + ota_1 + nvs
  sdkconfig.defaults              IDF tunables
  Kconfig.projbuild               white-label knobs
linux/                            Phase 2 placeholder
.github/workflows/build.yml       CI matrix: esp32, esp32s3
```
