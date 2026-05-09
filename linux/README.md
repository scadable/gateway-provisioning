# linux/ — Phase 2

Headless equivalent of the ESP provisioning firmware for `gateway-linux`
installs (Raspberry Pi, BeagleBone, x86_64 industrial PCs, etc.).

**Not implemented yet.** Sketch of the intended shape so the directory
isn't empty and so future contributors know where to put code:

- `gateway-provisioning.service` — systemd unit, runs on first boot
  before `gateway-linux.service`, blocks the gateway service until
  WiFi creds are written.
- `provisioning-portal/` — local web server (Python `http.server` or
  Go binary) listening on the install's wireless interface in AP
  mode. Same captive-portal UX as the ESP firmware.
- `nm-helpers/` — wraps `nmcli` calls for SoftAP setup +
  credential write to NetworkManager system connections.
- Recovery: holding a configurable GPIO (default same as ESP: pin 0
  on most SBCs) for 5s wipes saved creds.

Decision deferred until first customer with non-ESP hardware lands;
gateway-linux is currently x86_64-only and customers have always been
provisioning over Ethernet so AP mode hasn't been needed.

Until then, gateway-linux installs assume Ethernet at first boot and
use the existing `REGISTRATION_CODE` env var path.
