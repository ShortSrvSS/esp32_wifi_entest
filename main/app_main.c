/**
 * app_main.c
 *
 * 1. Initialize Wi-Fi STA (join PTCL-BB)
 * 2. Mount SPIFFS (for handshake.pcap)
 * 3. Start HTTP server
 */

#include <stdio.h>
#include "esp_log.h"
#include "wifi_station.h"
#include "http_server.h"
#include "esp_vfs_spiffs.h"

static const char* TAG = "app_main";

void app_main(void)
{
    ESP_LOGI(TAG, "=== Starting ESP32 Wi-Fi Pentest Tool ===");

    // 1) Connect to Wi-Fi STA (PTCL-BB)
    if (wifi_init_sta() != ESP_OK) {
        ESP_LOGE(TAG, "Failed to join Wi-Fi. Halting.");
        while (1) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
    ESP_LOGI(TAG, "Connected to Wi-Fi, IP: %s", wifi_get_ip_str());

    // 2) Mount SPIFFS (for storing handshake.pcap)
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "SPIFFS mount failed (%s)", esp_err_to_name(ret));
        return;
    }
    ESP_LOGI(TAG, "SPIFFS mounted at /spiffs");

    // 3) Start the HTTP server
    httpd_handle_t server = start_webserver();
    if (!server) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }
    ESP_LOGI(TAG, "HTTP server running. Visit: http://%s/scan", wifi_get_ip_str());
}
