// ap_provisioning.c — SoftAP + DNS sinkhole + captive portal HTTP
// server.
// SCADABLE 2026 · Apache-2.0
//
// The customer-facing surface. When this firmware decides the chip
// isn't ready to talk to the cloud yet (no WiFi creds, or saved
// network is gone, or cloud unreachable), we end up here.
//
// What runs:
//   - WiFi in AP mode, SSID "{PREFIX}-{MAC6}", IP 192.168.4.1
//     (PREFIX defaults to CONFIG_SCADABLE_COMPANY_NAME "-Setup", or
//     comes from branding.ssid_prefix in NVS — see branding.h)
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

#include "branding.h"
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
// external CSS, no external fonts, no JS bundles, no image URLs — the
// customer's phone is on the SoftAP (we're not bridging) and any
// off-device resource would 404. Icons are inline SVG.
//
// Layout: Mac-style WiFi list. Each row shows the SSID, a lock icon
// for secured networks, and 3 signal bars derived from RSSI. Tapping
// a row inline-expands a password field + Connect button below it.
// Open networks skip straight to a Connect button (no password). A
// "join hidden network" form lives at the bottom for SSIDs with
// broadcast off.

// ─── HTTP handlers ─────────────────────────────────────────────────

// Format args, in order:
//   1. page <title> (branding.title)
//   2. accent color override (CSS — replaces --orange CTA on .cta + .panel-mod retry)
//   3. brand banner HTML (either the default green dot OR an <img> tag
//                          with the customer's logo URL)
//   4. wordmark text (branding-derived, defaults to CONFIG_SCADABLE_COMPANY_NAME)
//   5. body HTML block (customer body OR the canonical default <p>
//                       with the AP SSID embedded)
//
// Note: every literal `%` in CSS (e.g. `width:100%`) must be doubled
// to `%%` because this string is fed through snprintf().
static const char setup_page_template_html[] =
    "<!doctype html>"
    "<html lang=\"en\">"
    "<head>"
    "<meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">"
    "<meta name=\"theme-color\" content=\"#100831\">"
    "<title>%s</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    ":root{--navy:#100831;--navy-2:#1a0f44;--surface:#1d1147;--surface-2:#251757;"
    "--cream:#F7ECE1;--cream-dim:rgba(247,236,225,.62);--cream-faint:rgba(247,236,225,.12);"
    "--turq:#0CE7D0;--orange:#F56300;--row-h:60px}"
    "html,body{background:var(--navy);color:var(--cream);min-height:100vh}"
    "body{font:15px/1.45 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
    "padding:env(safe-area-inset-top) 16px env(safe-area-inset-bottom);"
    "-webkit-font-smoothing:antialiased}"
    ".wrap{max-width:480px;margin:0 auto;padding:24px 0 40px}"
    ".brand{display:flex;align-items:center;gap:10px;margin-bottom:6px}"
    ".dot{width:10px;height:10px;border-radius:50%%;background:var(--turq);"
    "box-shadow:0 0 12px var(--turq)}"
    ".logo-img{width:24px;height:24px;border-radius:4px;object-fit:contain;"
    "background:rgba(247,236,225,.06)}"
    ".wordmark{font-weight:700;letter-spacing:.18em;font-size:13px;color:var(--cream)}"
    ".heading{font-size:24px;font-weight:600;margin-top:14px;color:var(--cream)}"
    ".sub{font-size:13px;color:var(--cream-dim);margin-top:4px}"
    ".sub code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;"
    "background:var(--cream-faint);padding:1px 6px;border-radius:4px}"
    ".bar{display:flex;align-items:center;justify-content:space-between;"
    "margin:24px 0 8px}"
    ".bar h2{font-size:11px;text-transform:uppercase;letter-spacing:.12em;"
    "color:var(--cream-dim);font-weight:600}"
    ".refresh{appearance:none;background:none;border:0;color:var(--turq);font:inherit;"
    "font-size:13px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;"
    "padding:6px 4px;min-height:32px}"
    ".refresh:disabled{opacity:.5;cursor:wait}"
    ".refresh svg{width:14px;height:14px}"
    ".refresh.spin svg{animation:spin 1s linear infinite}"
    "@keyframes spin{to{transform:rotate(360deg)}}"
    ".list{background:var(--surface);border:1px solid var(--cream-faint);"
    "border-radius:14px;overflow:hidden}"
    ".row{display:flex;align-items:center;gap:12px;width:100%%;min-height:var(--row-h);"
    "padding:10px 14px;background:transparent;border:0;border-bottom:1px solid var(--cream-faint);"
    "color:var(--cream);text-align:left;font:inherit;cursor:pointer;"
    "-webkit-tap-highlight-color:rgba(12,231,208,.12)}"
    ".row:last-child{border-bottom:0}"
    ".row:hover,.row:focus-visible{background:var(--surface-2);outline:none}"
    ".row[aria-expanded=true]{background:var(--surface-2)}"
    ".row .lock{width:14px;height:14px;flex:0 0 14px;color:var(--cream-dim)}"
    ".row .lock.empty{visibility:hidden}"
    ".row .name{flex:1;font-size:15px;font-weight:500;white-space:nowrap;"
    "overflow:hidden;text-overflow:ellipsis}"
    ".row .right{display:flex;align-items:center;gap:10px;flex:0 0 auto}"
    ".bars{display:inline-flex;align-items:flex-end;gap:2px;height:14px}"
    ".bars i{display:block;width:3px;background:var(--cream-dim);border-radius:1px}"
    ".bars i:nth-child(1){height:5px}"
    ".bars i:nth-child(2){height:9px}"
    ".bars i:nth-child(3){height:13px}"
    ".bars i.on{background:var(--turq)}"
    ".chev{width:10px;height:10px;color:var(--cream-dim);transition:transform .15s}"
    ".row[aria-expanded=true] .chev{transform:rotate(90deg);color:var(--turq)}"
    ".panel{display:none;padding:14px 16px 18px;background:var(--navy-2);"
    "border-bottom:1px solid var(--cream-faint)}"
    ".panel.open{display:block}"
    ".list .row + .panel{border-top:0}"
    ".plabel{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.1em;"
    "color:var(--cream-dim);margin-bottom:6px}"
    ".pwrap{position:relative}"
    "input[type=text],input[type=password]{width:100%%;background:var(--surface);"
    "color:var(--cream);border:1px solid var(--cream-faint);border-radius:10px;"
    "padding:12px 44px 12px 14px;font:inherit;min-height:44px}"
    "input:focus{outline:none;border-color:var(--turq);"
    "box-shadow:0 0 0 3px rgba(12,231,208,.18)}"
    ".eye{position:absolute;right:6px;top:50%%;transform:translateY(-50%%);"
    "background:none;border:0;color:var(--cream-dim);width:36px;height:36px;"
    "display:inline-flex;align-items:center;justify-content:center;cursor:pointer;"
    "border-radius:8px}"
    ".eye:hover{color:var(--turq)}"
    ".eye svg{width:18px;height:18px}"
    ".cta{display:block;width:100%%;margin-top:14px;background:var(--orange);"
    "color:#fff;border:0;padding:14px;border-radius:10px;"
    "font:600 15px/1 inherit;cursor:pointer;min-height:48px}"
    ".cta:hover{filter:brightness(1.08)}"
    ".cta:disabled{opacity:.55;cursor:not-allowed;filter:none}"
    ".cta.secondary{background:transparent;color:var(--turq);"
    "border:1px solid var(--cream-faint);font-weight:500}"
    ".perr{margin-top:10px;font-size:13px;color:#FFB199;min-height:18px}"
    ".empty,.skeleton{padding:18px 16px;color:var(--cream-dim);font-size:14px;"
    "text-align:center}"
    ".sk-row{display:flex;align-items:center;gap:12px;min-height:var(--row-h);"
    "padding:10px 14px;border-bottom:1px solid var(--cream-faint)}"
    ".sk-row:last-child{border-bottom:0}"
    ".sk{background:var(--cream-faint);border-radius:6px;height:12px;"
    "animation:pulse 1.4s ease-in-out infinite}"
    ".sk.lock{width:14px;height:14px;border-radius:3px;flex:0 0 14px}"
    ".sk.name{flex:1;max-width:60%%}"
    ".sk.bars{width:18px;height:14px}"
    "@keyframes pulse{0%%,100%%{opacity:.4}50%%{opacity:.85}}"
    ".hidden{margin-top:18px;background:var(--surface);border:1px solid var(--cream-faint);"
    "border-radius:14px;padding:14px 16px}"
    ".hidden summary{cursor:pointer;font-size:13px;color:var(--turq);"
    "list-style:none;display:flex;align-items:center;gap:8px;min-height:32px}"
    ".hidden summary::-webkit-details-marker{display:none}"
    ".hidden[open] summary{margin-bottom:12px}"
    ".hidden .stack{display:flex;flex-direction:column;gap:10px}"
    ".overlay{position:fixed;inset:0;background:rgba(16,8,49,.92);display:none;"
    "align-items:center;justify-content:center;padding:24px;z-index:10}"
    ".overlay.show{display:flex}"
    ".panel-mod{max-width:380px;width:100%%;background:var(--surface);"
    "border:1px solid var(--cream-faint);border-radius:14px;padding:24px;text-align:center}"
    ".panel-mod h3{font-size:18px;margin-bottom:8px;color:var(--cream)}"
    ".panel-mod p{font-size:14px;color:var(--cream-dim);margin-bottom:16px}"
    ".spinner{width:28px;height:28px;border-radius:50%%;border:3px solid var(--cream-faint);"
    "border-top-color:var(--turq);margin:0 auto 14px;animation:spin .8s linear infinite}"
    ".panel-mod.success .check{width:36px;height:36px;border-radius:50%%;background:var(--turq);"
    "color:var(--navy);display:inline-flex;align-items:center;justify-content:center;"
    "margin:0 auto 12px;font-size:20px;font-weight:700}"
    ".panel-mod .retry{margin-top:8px;background:var(--turq);color:var(--navy);"
    "border:0;padding:10px 18px;border-radius:8px;font:600 14px inherit;cursor:pointer}"
    ".foot{margin-top:24px;font-size:11px;color:var(--cream-dim);text-align:center;"
    "letter-spacing:.04em}"
    "</style>"
    // Accent color override (branding.accent_color). Wrapped in its
    // own <style> block so it can target only --orange without
    // re-doubling every `%` in the main stylesheet. snprintf injects
    // either the customer's color or the default #F56300.
    "<style>:root{--orange:%s}</style>"
    "</head>"
    "<body>"
    "<main class=\"wrap\">"
    // Brand banner: either the default green dot, or an <img> with
    // the customer's logo URL. The wordmark text falls back to the
    // company name.
    "<div class=\"brand\">%s"
    "<span class=\"wordmark\">%s</span></div>"
    "<h1 class=\"heading\">Setup device</h1>"
    // Body block: either the customer's body_html, or the canonical
    // default paragraph with the AP SSID baked in. handler_root
    // constructs the substitution server-side.
    "%s"

    "<div class=\"bar\">"
    "<h2>Networks</h2>"
    "<button type=\"button\" class=\"refresh\" id=\"rescan\" aria-label=\"Refresh networks\">"
    "<svg viewBox=\"0 0 16 16\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" "
    "stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">"
    "<path d=\"M14 8a6 6 0 1 1-1.76-4.24\"/><path d=\"M14 2v4h-4\"/></svg>"
    "<span>Refresh</span></button>"
    "</div>"

    "<div class=\"list\" id=\"list\" role=\"listbox\" aria-label=\"Available WiFi networks\">"
    "<div class=\"sk-row\"><div class=\"sk lock\"></div><div class=\"sk name\"></div>"
    "<div class=\"sk bars\"></div></div>"
    "<div class=\"sk-row\"><div class=\"sk lock\"></div><div class=\"sk name\"></div>"
    "<div class=\"sk bars\"></div></div>"
    "<div class=\"sk-row\"><div class=\"sk lock\"></div><div class=\"sk name\"></div>"
    "<div class=\"sk bars\"></div></div>"
    "</div>"

    "<details class=\"hidden\">"
    "<summary>+ Join a hidden network</summary>"
    "<form class=\"stack\" id=\"hidden-form\" autocomplete=\"off\">"
    "<div><span class=\"plabel\">Network name</span>"
    "<input type=\"text\" id=\"h-ssid\" required maxlength=\"32\" "
    "autocapitalize=\"none\" autocorrect=\"off\" spellcheck=\"false\"></div>"
    "<div><span class=\"plabel\">Password</span>"
    "<div class=\"pwrap\"><input type=\"password\" id=\"h-pass\" "
    "autocomplete=\"new-password\" maxlength=\"63\">"
    "<button type=\"button\" class=\"eye\" data-eye=\"h-pass\" aria-label=\"Show password\">"
    "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" "
    "stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">"
    "<path d=\"M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z\"/>"
    "<circle cx=\"12\" cy=\"12\" r=\"3\"/></svg></button></div></div>"
    "<button type=\"submit\" class=\"cta\">Connect</button>"
    "<div class=\"perr\" id=\"h-err\"></div>"
    "</form>"
    "</details>"

    "<p class=\"foot\">Setup AP - safe to disconnect after the device joins WiFi.</p>"
    "</main>"

    "<div class=\"overlay\" id=\"ov\" role=\"dialog\" aria-modal=\"true\" aria-live=\"polite\">"
    "<div class=\"panel-mod\" id=\"ov-card\">"
    "<div class=\"spinner\" id=\"ov-spin\" aria-hidden=\"true\"></div>"
    "<div class=\"check\" id=\"ov-check\" style=\"display:none\" aria-hidden=\"true\">&#10003;</div>"
    "<h3 id=\"ov-title\">Connecting&hellip;</h3>"
    "<p id=\"ov-msg\">Saving credentials and rebooting the device.</p>"
    "<button type=\"button\" class=\"retry\" id=\"ov-retry\" style=\"display:none\">Try again</button>"
    "</div>"
    "</div>"

    "<script>"
    "(function(){"
    "const $=s=>document.querySelector(s);"
    "const list=$('#list');const rescan=$('#rescan');"
    "const ov=$('#ov');const ovSpin=$('#ov-spin');const ovCheck=$('#ov-check');"
    "const ovTitle=$('#ov-title');const ovMsg=$('#ov-msg');const ovRetry=$('#ov-retry');"
    "const ovCard=$('#ov-card');"
    "let scanning=false;let pollTimer=null;let openIdx=-1;let networks=[];"

    "function esc(s){return String(s).replace(/[&<>\"']/g,c=>(\"&#\"+c.charCodeAt(0)+\";\"))}"
    "function bars(rssi){if(rssi>=-55)return 3;if(rssi>=-70)return 2;if(rssi>=-82)return 1;return 0}"
    "function lockSvg(secure){return secure"
    "?'<svg class=\"lock\" viewBox=\"0 0 16 16\" fill=\"none\" stroke=\"currentColor\" "
    "stroke-width=\"1.4\" aria-label=\"secured\"><rect x=\"3\" y=\"7\" width=\"10\" height=\"7\" "
    "rx=\"1.5\"/><path d=\"M5 7V5a3 3 0 0 1 6 0v2\"/></svg>'"
    ":'<span class=\"lock empty\" aria-hidden=\"true\"></span>'}"
    "function barsSvg(level){let h='<span class=\"bars\" aria-label=\"signal '+level+' of 3\">';"
    "for(let i=1;i<=3;i++)h+='<i class=\"'+(i<=level?'on':'')+'\"></i>';return h+'</span>'}"
    "function chevSvg(){return '<svg class=\"chev\" viewBox=\"0 0 10 10\" fill=\"none\" "
    "stroke=\"currentColor\" stroke-width=\"1.6\" stroke-linecap=\"round\" "
    "stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M3 1l4 4-4 4\"/></svg>'}"

    "function renderEmpty(msg){list.innerHTML='<div class=\"empty\">'+esc(msg)+'</div>'}"
    "function renderSkeleton(){list.innerHTML="
    "'<div class=\"sk-row\"><div class=\"sk lock\"></div><div class=\"sk name\"></div>"
    "<div class=\"sk bars\"></div></div>'.repeat(3)}"

    "function render(){"
    "if(!networks.length){renderEmpty('No networks found. Try Refresh.');return}"
    "let h='';networks.forEach((n,i)=>{"
    "const lvl=bars(n.rssi);"
    "h+='<button type=\"button\" class=\"row\" role=\"option\" data-i=\"'+i+'\" "
    "aria-expanded=\"'+(i===openIdx)+'\">'"
    "+lockSvg(n.secure)+'<span class=\"name\">'+esc(n.ssid||'(no name)')+'</span>'"
    "+'<span class=\"right\">'+barsSvg(lvl)+chevSvg()+'</span>'"
    "+'</button>';"
    "h+='<div class=\"panel'+(i===openIdx?' open':'')+'\" id=\"p'+i+'\">';"
    "if(n.secure){"
    "h+='<span class=\"plabel\">Password for '+esc(n.ssid)+'</span>'"
    "+'<div class=\"pwrap\"><input type=\"password\" id=\"pw'+i+'\" "
    "autocomplete=\"new-password\" maxlength=\"63\" '"
    "+(i===openIdx?'autofocus':'')+'>'"
    "+'<button type=\"button\" class=\"eye\" data-eye=\"pw'+i+'\" "
    "aria-label=\"Show password\">'"
    "+'<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" "
    "stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\" "
    "aria-hidden=\"true\"><path d=\"M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z\"/>"
    "<circle cx=\"12\" cy=\"12\" r=\"3\"/></svg></button></div>'"
    "+'<button type=\"button\" class=\"cta\" data-go=\"'+i+'\">Connect</button>';"
    "}else{"
    "h+='<p class=\"plabel\" style=\"text-transform:none;letter-spacing:0;font-size:13px\">"
    "This is an open network - no password needed.</p>'"
    "+'<button type=\"button\" class=\"cta\" data-go=\"'+i+'\">Connect</button>';"
    "}"
    "h+='<div class=\"perr\" id=\"err'+i+'\"></div></div>';"
    "});"
    "list.innerHTML=h;"
    "}"

    "async function scan(){"
    "if(scanning)return;scanning=true;"
    "rescan.disabled=true;rescan.classList.add('spin');"
    "if(!networks.length)renderSkeleton();"
    "try{"
    "const r=await fetch('/scan',{cache:'no-store'});"
    "const j=await r.json();"
    "networks=(j.networks||[]).slice().sort((a,b)=>(b.rssi||-100)-(a.rssi||-100));"
    "openIdx=-1;render();"
    "}catch(e){renderEmpty('Scan failed - tap Refresh to retry.')}"
    "finally{scanning=false;rescan.disabled=false;rescan.classList.remove('spin')}"
    "}"

    "list.addEventListener('click',e=>{"
    "const eye=e.target.closest('[data-eye]');"
    "if(eye){const id=eye.getAttribute('data-eye');const inp=document.getElementById(id);"
    "if(inp){inp.type=inp.type==='password'?'text':'password';"
    "eye.setAttribute('aria-label',inp.type==='password'?'Show password':'Hide password')}return}"
    "const go=e.target.closest('[data-go]');"
    "if(go){const i=+go.getAttribute('data-go');connect(networks[i],i);return}"
    "const row=e.target.closest('.row');"
    "if(row){const i=+row.getAttribute('data-i');openIdx=(openIdx===i?-1:i);render();"
    "if(openIdx===i){const inp=document.getElementById('pw'+i);if(inp)inp.focus()}}"
    "});"

    "list.addEventListener('keydown',e=>{"
    "if(e.key!=='Enter')return;"
    "const inp=e.target.closest('input[type=password],input[type=text]');"
    "if(!inp)return;"
    "const m=inp.id.match(/^pw(\\d+)$/);if(!m)return;"
    "e.preventDefault();const i=+m[1];connect(networks[i],i);"
    "});"

    "rescan.addEventListener('click',()=>{networks=[];scan()});"

    "$('#hidden-form').addEventListener('submit',e=>{"
    "e.preventDefault();"
    "const ssid=$('#h-ssid').value.trim();const pass=$('#h-pass').value;"
    "if(!ssid){$('#h-err').textContent='Network name is required.';return}"
    "$('#h-err').textContent='';connect({ssid:ssid,secure:!!pass},'h',pass);"
    "});"

    "function showOverlay(state,title,msg){"
    "ov.classList.add('show');ovCard.classList.toggle('success',state==='success');"
    "ovSpin.style.display=state==='loading'?'block':'none';"
    "ovCheck.style.display=state==='success'?'inline-flex':'none';"
    "ovRetry.style.display=state==='error'?'inline-block':'none';"
    "ovTitle.textContent=title;ovMsg.textContent=msg;"
    "}"
    "function hideOverlay(){ov.classList.remove('show')}"
    "ovRetry.addEventListener('click',hideOverlay);"

    "async function connect(net,idx,explicitPass){"
    "if(!net||!net.ssid){return}"
    "let pass=explicitPass;"
    "if(pass===undefined&&net.secure){"
    "const inp=document.getElementById('pw'+idx);pass=inp?inp.value:''"
    "}"
    "if(pass===undefined)pass='';"
    "if(pollTimer){clearInterval(pollTimer);pollTimer=null}"
    "showOverlay('loading','Connecting to '+net.ssid,"
    "'Saving credentials and rebooting the device.');"
    "try{"
    "const r=await fetch('/connect',{method:'POST',"
    "headers:{'content-type':'application/json'},"
    "body:JSON.stringify({ssid:net.ssid,password:pass})});"
    "if(r.ok){"
    "showOverlay('success','Saved',"
    "'This page will close - your phone should reconnect to its regular WiFi shortly.');"
    "}else{"
    "let detail='HTTP '+r.status;"
    "try{const j=await r.json();if(j&&j.error)detail=j.error}catch(_){}"
    "showOverlay('error','Could not save',detail);"
    "}"
    "}catch(e){"
    "showOverlay('error','Network error',"
    "'The device dropped the connection. If WiFi joined successfully this is expected.');"
    "}"
    "}"

    "scan();pollTimer=setInterval(()=>{if(!ov.classList.contains('show'))scan()},20000);"
    "})();"
    "</script>"
    "</body></html>";

// Serve the setup page. Renders the customer's branding template
// (title, body HTML, SSID, accent color, logo URL) into the HTML,
// falling back to firmware defaults for any field the org hasn't
// customized. We use a heap buffer because the rendered HTML can run
// 20+ KB once branding is applied and we want to keep the stack small.
static esp_err_t handler_root(httpd_req_t *req)
{
    char ap_ssid[33] = {0};
    wifi_config_t cfg;
    if (esp_wifi_get_config(WIFI_IF_AP, &cfg) == ESP_OK) {
        strncpy(ap_ssid, (const char *)cfg.ap.ssid, sizeof(ap_ssid) - 1);
    } else {
        strcpy(ap_ssid, "(unknown)");
    }

    // Load org branding from NVS namespace `scadable_brand`. Every
    // field independently falls back to its compile-time default when
    // the key is missing, so an un-branded chip still produces well-
    // formed HTML (this is the steady state for the SCADABLE-owned
    // factory firmware before any customer ever sees it).
    branding_t br;
    branding_load(&br);

    // Build the brand-banner block. With a logo URL we emit an <img>;
    // without one, the default green dot. Sized to fit either form.
    char banner[BRANDING_LOGO_MAX + 256] = {0};
    if (br.logo_url[0]) {
        snprintf(banner, sizeof(banner),
                 "<img class=\"logo-img\" src=\"%s\" alt=\"\">",
                 br.logo_url);
    } else {
        snprintf(banner, sizeof(banner),
                 "<span class=\"dot\" aria-hidden=\"true\"></span>");
    }

    // Wordmark text — defaults to the company name if the customer
    // hasn't customized. Reuse the title's first word as a tasteful
    // fallback wordmark only when no title is set; if branding.title
    // IS set, we still want the wordmark to be the company-ish name,
    // so derive from ssid_prefix (which the customer also sets) by
    // stripping the "-Setup" suffix if present.
    char wordmark[BRANDING_SSID_MAX] = {0};
    strncpy(wordmark, br.ssid_prefix, sizeof(wordmark) - 1);
    wordmark[sizeof(wordmark) - 1] = '\0';
    // Lop off a trailing "-Setup" so "Acme-Setup" displays as "Acme".
    size_t wm_len = strlen(wordmark);
    static const char setup_suffix[] = "-Setup";
    static const size_t setup_suffix_len = sizeof(setup_suffix) - 1;
    if (wm_len >= setup_suffix_len &&
        strcmp(wordmark + wm_len - setup_suffix_len, setup_suffix) == 0) {
        wordmark[wm_len - setup_suffix_len] = '\0';
    }
    if (wordmark[0] == '\0') {
        strncpy(wordmark, CONFIG_SCADABLE_COMPANY_NAME, sizeof(wordmark) - 1);
    }

    // Build the body block. With a customer body_html, use it verbatim
    // (no sanitization — this is the customer's own org's branding,
    // gated admin-only at write time on the cloud side). Without one,
    // render the canonical default paragraph with the AP SSID embedded.
    char body[BRANDING_BODY_MAX + 256] = {0};
    if (br.body[0]) {
        // Customer-supplied body. Wrap in nothing — the customer can
        // bring their own <p>s, <h2>s, etc.
        snprintf(body, sizeof(body), "%s", br.body);
    } else {
        snprintf(body, sizeof(body),
                 "<p class=\"sub\">Pick the WiFi network this gateway should use. "
                 "You're connected to <code>%s</code>.</p>",
                 ap_ssid);
    }

    // 24 KB upper bound — base template is ~15 KB; branding can add
    // up to ~2.5 KB of customer body HTML + ~500 B of logo URL +
    // smaller fields. Generous headroom over the worst case.
    enum { SETUP_PAGE_BUF = 24576 };
    char *buf = malloc(SETUP_PAGE_BUF);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_FAIL;
    }
    int n = snprintf(buf, SETUP_PAGE_BUF, setup_page_template_html,
                     br.title,         // <title>
                     br.accent_color,  // CSS --orange override
                     banner,           // brand-banner HTML
                     wordmark,         // wordmark text
                     body);            // body block
    if (n < 0 || n >= SETUP_PAGE_BUF) {
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

// Build SSID "{PREFIX}-{6 hex chars from MAC}" into the caller's
// buffer. e.g. "Acme-Setup-A4F3B2" when the org has set
// branding.ssid_prefix = "Acme-Setup"; otherwise the firmware default
// "SCADABLE-Setup-A4F3B2". The MAC-suffix logic is preserved verbatim
// — only the prefix is customizable.
static void build_ap_ssid(char *out, size_t cap)
{
    branding_t br;
    branding_load(&br);

    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(out, cap, "%s-%02X%02X%02X",
             br.ssid_prefix, mac[3], mac[4], mac[5]);
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

    // SSID already contains the customer's (or default) prefix —
    // see build_ap_ssid which reads branding.ssid_prefix from NVS.
    ESP_LOGI(TAG, "Starting setup AP: SSID=\"%s\" IP=%s", ssid, SETUP_AP_IP);

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
