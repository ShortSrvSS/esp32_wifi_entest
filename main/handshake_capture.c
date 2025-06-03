#include <string.h>
#include <stdlib.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "pcap_writer.h"

static const char *TAG = "handshake_capture";

static wifi_promiscuous_cb_t orig_cb = NULL;
static pcap_writer_t *pcap_writer = NULL;

static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    if (type == WIFI_PKT_MGMT) {
        // Capture handshake packets logic
        pcap_writer_write(pcap_writer, pkt->payload, pkt->rx_ctrl.sig_len);
    }

    if (orig_cb) {
        orig_cb(buf, type);
    }
}

esp_err_t handshake_deauth_and_capture(void) {
    esp_err_t err;

    // Initialize PCAP writer
    pcap_writer = pcap_writer_init("/spiffs/handshake.pcap");
    if (!pcap_writer) {
        ESP_LOGE(TAG, "Failed to initialize pcap_writer");
        return ESP_FAIL;
    }

    // Save original promiscuous callback
    orig_cb = esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    // Start promiscuous mode
    err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set promiscuous mode: %d", err);
        return err;
    }

    // Deauth broadcast frame sending (simplified, customize as needed)
    // ... your deauth logic here ...

    // Wait for handshake capture timeout (e.g. 15 seconds)
    int64_t start_time = esp_timer_get_time() / 1000;
    while ((esp_timer_get_time() / 1000) - start_time < 15000) {
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    // Stop promiscuous mode
    esp_wifi_set_promiscuous(false);

    // Close pcap file
    pcap_writer_close(pcap_writer);

    return ESP_OK;
}
