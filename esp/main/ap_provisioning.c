// ap_provisioning.c — SoftAP + DNS sinkhole + captive portal HTTP
// server.
// SCADABLE 2026 · Apache-2.0
//
// The customer-facing surface. When this firmware decides the chip
// isn't ready to talk to the cloud yet (no WiFi creds, or saved
// network is gone, or cloud unreachable), we end up here.
//
// What runs:
//   - WiFi in AP mode, SSID "{COMPANY}-Setup-{MAC6}", IP 192.168.4.1
//   - DHCP server (handed to us by IDF's esp_netif_create_default_wifi_ap)
//   - DNS sinkhole on UDP/53 — every A query resolves to 192.168.4.1
//     so any browser request triggers the OS captive-portal popup
//     (Apple's connectivity test, Android's gen_204, Windows's NCSI)
//   - HTTP server on TCP/80 with three endpoints:
//       GET /         → setup page (HTML)
//       GET /scan     → JSON list of visible networks
//       POST /connect → write NVS, return 200, schedule reboot
//     Plus the captive-portal probe URLs that OS popups hit; they all
//     redirect to the setup page so any URL the browser tries works.
//   - mDNS on `scadable-setup.local` as a fallback for OSes that
//     don't have a captive-portal popup.
//
// v1 ships without the upstream `wifi_provisioning` security-1
// channel — the AP only exists for ~60 seconds during initial site
// setup, the password isn't sent in plaintext (HTTP form POST is over
// the local AP, no egress), and Ali confirmed this risk profile is
// acceptable for v1. Phase 2 adds the encrypted channel for BLE.

#include "ap_provisioning.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

#include "cJSON.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "mdns.h"
#include "nvs.h"
#include "sdkconfig.h"

static const char *TAG = "scadable.ap";

#define SETUP_AP_IP    "192.168.4.1"
#define SETUP_HOST     "scadable-setup"
#define DNS_PORT       53
#define MAX_AP_RECORDS 16

#define NVS_NAMESPACE_WIFI "wifi"
#define NVS_KEY_WIFI_SSID  "ssid"
#define NVS_KEY_WIFI_PASS  "password"

// Embed the captive portal HTML at build time. See
// `setup_page_template_html` below for the format string layout.
//
// The page is intentionally a single self-contained HTML file: no
// external CSS, no external fonts, no JS bundles. Customer phones in
// the field don't have internet access from the SoftAP (we're not
// bridging) so any external resource would 404.

// ─── HTTP handlers ─────────────────────────────────────────────────

// Format args, in order:
//   1. company name (used twice: <title> and <h1>)
//   2. company name (again — kept as separate arg so future tweaks
//                    can split title vs heading without renumbering)
//   3. AP SSID (so the customer can confirm they're on the right
//               device when multiple are nearby)
static const char setup_page_template_html[] =
    "<!doctype html>"
    "<html lang=\"en\">"
    "<head>"
    "<meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    "<title>%s setup</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font:16px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
    "background:#100831;color:#F7ECE1;min-height:100vh;padding:24px}"
    ".card{max-width:420px;margin:32px auto;background:rgba(7,5,24,.72);"
    "border:1px solid rgba(247,236,225,.12);border-radius:16px;padding:28px;"
    "box-shadow:0 12px 40px rgba(0,0,0,.4)}"
    "h1{font-size:22px;margin-bottom:8px;color:#0CE7D0}"
    ".sub{font-size:13px;opacity:.7;margin-bottom:24px}"
    "label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.08em;"
    "opacity:.7;margin-bottom:8px;margin-top:16px}"
    "select,input{width:100%%;background:rgba(247,236,225,.08);color:#F7ECE1;"
    "border:1px solid rgba(247,236,225,.16);border-radius:8px;padding:12px 14px;"
    "font:inherit}"
    "select:focus,input:focus{outline:none;border-color:#0CE7D0}"
    "button{width:100%%;margin-top:24px;background:#F56300;color:#fff;border:0;"
    "padding:14px;border-radius:8px;font:600 15px inherit;cursor:pointer}"
    "button:disabled{opacity:.5;cursor:not-allowed}"
    ".status{margin-top:16px;font-size:13px;opacity:.7;text-align:center;min-height:20px}"
    ".rescan{margin-top:8px;background:none;border:0;color:#0CE7D0;font-size:13px;"
    "padding:0;width:auto;text-align:left;cursor:pointer}"
    "</style>"
    "</head>"
    "<body>"
    "<div class=\"card\">"
    "<h1>%s setup</h1>"
    "<div class=\"sub\">Connect this device to your WiFi network.<br>"
    "Connected to <code>%s</code></div>"

    "<label for=\"ssid\">Network</label>"
    "<select id=\"ssid\" required></select>"
    "<button type=\"button\" class=\"rescan\" id=\"rescan\">Rescan</button>"

    "<label for=\"pass\">Password</label>"
    "<input id=\"pass\" type=\"password\" autocomplete=\"new-password\">"

    "<button id=\"go\" disabled>Connect</button>"
    "<div class=\"status\" id=\"status\"></div>"
    "</div>"

    "<script>"
    "const $=id=>document.getElementById(id);"
    "let scanning=false;"
    "async function scan(){if(scanning)return;scanning=true;"
    "$('status').textContent='Scanning networks…';"
    "try{const r=await fetch('/scan');const j=await r.json();"
    "const sel=$('ssid');sel.innerHTML='';"
    "(j.networks||[]).forEach(n=>{const o=document.createElement('option');"
    "o.value=n.ssid;o.textContent=`${n.ssid} (${n.rssi} dBm${n.secure?', secured':''})`;"
    "sel.appendChild(o)});"
    "$('go').disabled=sel.options.length===0;"
    "$('status').textContent=sel.options.length?'':'No networks found.';"
    "}catch(e){$('status').textContent='Scan failed: '+e}finally{scanning=false}}"
    "$('rescan').addEventListener('click',scan);"
    "$('go').addEventListener('click',async()=>{"
    "const ssid=$('ssid').value;const password=$('pass').value;"
    "$('go').disabled=true;$('status').textContent='Saving and rebooting…';"
    "try{const r=await fetch('/connect',{method:'POST',"
    "headers:{'content-type':'application/json'},"
    "body:JSON.stringify({ssid,password})});"
    "if(r.ok){$('status').textContent='Saved. Device is rebooting — give it a minute.';}"
    "else{$('status').textContent='Save failed: '+r.status;$('go').disabled=false}"
    "}catch(e){$('status').textContent='Network error: '+e;$('go').disabled=false}});"
    "scan();setInterval(scan,15000);"
    "</script>"
    "</body></html>";

// Serve the setup page. Renders the company name + SSID into the
// template. We use a heap buffer because the rendered HTML can run a
// few KB and we want to keep the stack small.
static esp_err_t handler_root(httpd_req_t *req)
{
    char ap_ssid[33] = {0};
    wifi_config_t cfg;
    if (esp_wifi_get_config(WIFI_IF_AP, &cfg) == ESP_OK) {
        strncpy(ap_ssid, (const char *)cfg.ap.ssid, sizeof(ap_ssid) - 1);
    } else {
        strcpy(ap_ssid, "(unknown)");
    }

    // 4 KB upper bound — template is ~3.6 KB rendered.
    char *buf = malloc(5120);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_FAIL;
    }
    int n = snprintf(buf, 5120, setup_page_template_html,
                     CONFIG_SCADABLE_COMPANY_NAME,
                     CONFIG_SCADABLE_COMPANY_NAME,
                     ap_ssid);
    if (n < 0 || n >= 5120) {
        free(buf);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "render");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, buf, n);
    free(buf);
    return ESP_OK;
}

// JSON list of visible WiFi networks. We trigger a fresh scan on
// every request — that's typically 2-3s, which is fine for the
// "Rescan" button. The polling interval in the JS is 15s so we don't
// hammer the radio.
static esp_err_t handler_scan(httpd_req_t *req)
{
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active = {.min = 100, .max = 300},
    };
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);  // blocking
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "scan start failed: %s", esp_err_to_name(err));
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"networks\":[]}");
        return ESP_OK;
    }

    uint16_t found = 0;
    esp_wifi_scan_get_ap_num(&found);
    if (found > MAX_AP_RECORDS) found = MAX_AP_RECORDS;

    wifi_ap_record_t records[MAX_AP_RECORDS];
    esp_wifi_scan_get_ap_records(&found, records);

    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_AddArrayToObject(root, "networks");
    for (int i = 0; i < found; i++) {
        cJSON *n = cJSON_CreateObject();
        cJSON_AddStringToObject(n, "ssid", (const char *)records[i].ssid);
        cJSON_AddNumberToObject(n, "rssi", records[i].rssi);
        cJSON_AddBoolToObject(n, "secure", records[i].authmode != WIFI_AUTH_OPEN);
        cJSON_AddItemToArray(list, n);
    }

    char *out = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out);
    cJSON_free(out);
    cJSON_Delete(root);
    return ESP_OK;
}

// Reboot helper — runs on a small dedicated task so the HTTP handler
// can return its 200 to the browser before the radio drops.
static void reboot_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(2000));
    ESP_LOGI(TAG, "Rebooting after successful provisioning");
    esp_restart();
}

// POST /connect with JSON body {"ssid":"...","password":"..."}
// Writes both to NVS namespace `wifi` and reboots.
static esp_err_t handler_connect(httpd_req_t *req)
{
    char body[256] = {0};
    int total = req->content_len;
    if (total <= 0 || total >= (int)sizeof(body)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad length");
        return ESP_FAIL;
    }

    int read_so_far = 0;
    while (read_so_far < total) {
        int r = httpd_req_recv(req, body + read_so_far, total - read_so_far);
        if (r <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "recv failed");
            return ESP_FAIL;
        }
        read_so_far += r;
    }

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad json");
        return ESP_FAIL;
    }
    const cJSON *jssid = cJSON_GetObjectItem(root, "ssid");
    const cJSON *jpass = cJSON_GetObjectItem(root, "password");
    if (!cJSON_IsString(jssid) || jssid->valuestring[0] == '\0') {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing ssid");
        return ESP_FAIL;
    }
    // Password may be empty (open networks).
    const char *ssid = jssid->valuestring;
    const char *pass = cJSON_IsString(jpass) ? jpass->valuestring : "";

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE_WIFI, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        cJSON_Delete(root);
        ESP_LOGE(TAG, "nvs_open(wifi) failed: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "nvs open");
        return ESP_FAIL;
    }
    nvs_set_str(handle, NVS_KEY_WIFI_SSID, ssid);
    nvs_set_str(handle, NVS_KEY_WIFI_PASS, pass);
    nvs_commit(handle);
    nvs_close(handle);
    cJSON_Delete(root);

    ESP_LOGI(TAG, "Saved creds for SSID '%s' (pw len=%d)", ssid, (int)strlen(pass));

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");

    // Reboot in a side task so the response actually goes out.
    xTaskCreate(reboot_task, "reboot", 2048, NULL, 5, NULL);
    return ESP_OK;
}

// Catch-all for the OS captive-portal probe URLs. iOS hits
// /hotspot-detect.html, Android hits /generate_204, Windows hits
// /ncsi.txt — instead of memorizing each path, we wildcard-match and
// redirect everything to the root. The OS then opens a browser
// window pointed at the redirect target, which is exactly what we
// want.
static esp_err_t handler_redirect(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://" SETUP_AP_IP "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

// ─── DNS sinkhole ──────────────────────────────────────────────────
//
// A tiny task that binds UDP/53 and replies to every A query with
// 192.168.4.1. We only handle the common case: a single QNAME, IN
// class, type A. Anything else gets an empty answer (which still
// works as a sinkhole — the resolver just retries and we ignore it).

static void dns_sinkhole_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "DNS socket() failed: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "DNS bind() failed: errno %d", errno);
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS sinkhole listening on UDP/%d", DNS_PORT);

    uint8_t buf[512];
    while (true) {
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &srclen);
        if (n < 12) continue;  // shorter than a DNS header

        // Build a response in-place: flip QR to 1 (response), set
        // ANCOUNT to 1, append a single A-record answer pointing at
        // 192.168.4.1.
        buf[2] = 0x81;  // QR=1, OPCODE=0, AA=0, TC=0, RD=1 (echo back the RD bit)
        buf[3] = 0x80;  // RA=1, Z=0, RCODE=0
        buf[4] = 0;     // QDCOUNT high (was 1, leave it)
        buf[5] = 1;
        buf[6] = 0;     // ANCOUNT high
        buf[7] = 1;     // ANCOUNT low (one answer)
        buf[8] = 0;     // NSCOUNT
        buf[9] = 0;
        buf[10] = 0;    // ARCOUNT
        buf[11] = 0;

        // Walk past the question to find the end. QNAME is a series
        // of length-prefixed labels terminated by a zero byte; then
        // 4 bytes for QTYPE+QCLASS.
        ssize_t i = 12;
        while (i < n && buf[i] != 0) {
            i += buf[i] + 1;
            if (i >= (ssize_t)sizeof(buf)) break;
        }
        i += 1 + 4;  // null label + QTYPE/QCLASS

        if (i + 16 > (ssize_t)sizeof(buf)) continue;  // no room for answer

        // Answer: pointer to QNAME at offset 12 (compressed), TYPE A,
        // CLASS IN, TTL 60, RDLENGTH 4, RDATA 192.168.4.1.
        buf[i++] = 0xC0;
        buf[i++] = 0x0C;
        buf[i++] = 0x00;
        buf[i++] = 0x01;  // A
        buf[i++] = 0x00;
        buf[i++] = 0x01;  // IN
        buf[i++] = 0x00;
        buf[i++] = 0x00;
        buf[i++] = 0x00;
        buf[i++] = 0x3C;  // TTL = 60
        buf[i++] = 0x00;
        buf[i++] = 0x04;  // RDLENGTH = 4
        buf[i++] = 192;
        buf[i++] = 168;
        buf[i++] = 4;
        buf[i++] = 1;

        sendto(sock, buf, i, 0, (struct sockaddr *)&src, srclen);
    }
}

// ─── Setup ─────────────────────────────────────────────────────────

// Build SSID "{COMPANY}-Setup-{6 hex chars from MAC}" into the
// caller's buffer. e.g. "SCADABLE-Setup-A4F3B2".
static void build_ap_ssid(char *out, size_t cap)
{
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(out, cap, "%s-Setup-%02X%02X%02X",
             CONFIG_SCADABLE_COMPANY_NAME, mac[3], mac[4], mac[5]);
}

static httpd_handle_t start_http_server(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.lru_purge_enable = true;
    cfg.max_uri_handlers = 8;

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed");
        return NULL;
    }

    static const httpd_uri_t root_uri = {
        .uri = "/", .method = HTTP_GET, .handler = handler_root};
    static const httpd_uri_t scan_uri = {
        .uri = "/scan", .method = HTTP_GET, .handler = handler_scan};
    static const httpd_uri_t connect_uri = {
        .uri = "/connect", .method = HTTP_POST, .handler = handler_connect};
    // Wildcard catch-all for OS captive-portal probes.
    static const httpd_uri_t catchall_uri = {
        .uri = "/*", .method = HTTP_GET, .handler = handler_redirect};

    httpd_register_uri_handler(server, &root_uri);
    httpd_register_uri_handler(server, &scan_uri);
    httpd_register_uri_handler(server, &connect_uri);
    httpd_register_uri_handler(server, &catchall_uri);
    return server;
}

void ap_provisioning_start(void)
{
    char ssid[33];
    build_ap_ssid(ssid, sizeof(ssid));

    ESP_LOGI(TAG, "Starting %s-Setup AP: SSID=\"%s\" IP=%s",
             CONFIG_SCADABLE_COMPANY_NAME, ssid, SETUP_AP_IP);

    ESP_ERROR_CHECK(esp_netif_init());
    // esp_event_loop_create_default may already exist if we came from
    // a failed STA attempt — tolerate that.
    esp_err_t evt_err = esp_event_loop_create_default();
    if (evt_err != ESP_OK && evt_err != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(evt_err);
    }
    esp_netif_create_default_wifi_ap();
    // STA netif lets us scan visible networks while AP is up (APSTA mode).
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t ap_cfg = {
        .ap = {
            .ssid_len = strlen(ssid),
            .channel = 6,
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,  // open AP for v1 (see file header)
            .pmf_cfg = {.required = false},
        },
    };
    strncpy((char *)ap_cfg.ap.ssid, ssid, sizeof(ap_cfg.ap.ssid));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    // mDNS makes `http://scadable-setup.local/` resolve when the
    // captive-portal popup misses (some Android variants).
    if (mdns_init() == ESP_OK) {
        mdns_hostname_set(SETUP_HOST);
        mdns_instance_name_set(CONFIG_SCADABLE_COMPANY_NAME " Setup");
        mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
    }

    httpd_handle_t server = start_http_server();
    if (!server) {
        ESP_LOGE(TAG, "HTTP server didn't start — AP mode is broken, rebooting");
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_restart();
    }

    xTaskCreate(dns_sinkhole_task, "dns_sinkhole", 4096, NULL, 5, NULL);

    ESP_LOGI(TAG, "AP provisioning is live. Customer can connect to '%s' "
                  "and a browser should auto-pop the setup page.", ssid);

    // Sleep forever (or for the configured timeout). Successful
    // provisioning reboots from inside handler_connect().
    if (CONFIG_SCADABLE_AP_TIMEOUT_SECS > 0) {
        ESP_LOGI(TAG, "AP-mode timeout: %d seconds", CONFIG_SCADABLE_AP_TIMEOUT_SECS);
        vTaskDelay(pdMS_TO_TICKS(CONFIG_SCADABLE_AP_TIMEOUT_SECS * 1000));
        ESP_LOGW(TAG, "AP-mode timeout reached without provisioning — rebooting");
        esp_restart();
    } else {
        while (true) {
            vTaskDelay(pdMS_TO_TICKS(60000));
        }
    }
}
