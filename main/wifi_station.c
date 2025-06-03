/**
 * wifi_station.c
 *
 * Implements:
 *  - Connecting to Wi-Fi STA (using credentials in sdkconfig)
 *  - One-shot scanning of all nearby APs
 */

#include "wifi_station.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include <string.h>
#include <stdlib.h>

static const char* TAG = "wifi_sta";

/* Track connection state */
static bool s_connected = false;
static char s_ip_str[16] = { 0 };

static void on_wifi_event(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Disconnected, retrying...");
        esp_wifi_connect();
        s_connected = false;
    }
}

static void on_ip_event(void* arg, esp_event_base_t event_base,
                        int32_t event_id, void* event_data)
{
    ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
    const esp_netif_ip_info_t* ip_info = &event->ip_info;
    snprintf(s_ip_str, sizeof(s_ip_str), "%u.%u.%u.%u",
             IP2STR(&ip_info->ip));
    ESP_LOGI(TAG, "Got IP: %s", s_ip_str);
    s_connected = true;
}

esp_err_t wifi_init_sta(void)
{
    // 1) Init NVS (needed by Wi-Fi)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 2) Init TCP/IP stack and event loop
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    // Create default STA netif
    esp_netif_t* netif_sta = esp_netif_create_default_wifi_sta();
    assert(netif_sta);

    // 3) Init Wi-Fi driver
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // 4) Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &on_ip_event, NULL, NULL));

    // 5) Configure STA with SSID/PASS from sdkconfig
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = CONFIG_WIFI_SSID,
            .password = CONFIG_WIFI_PASSWORD,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to Wi-Fi SSID: %s …", CONFIG_WIFI_SSID);

    // 6) Wait until connected or timeout (~15 seconds)
    uint32_t retry = 0;
    while (!s_connected && retry++ < 150) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (!s_connected) {
        ESP_LOGE(TAG, "Failed to connect to %s", CONFIG_WIFI_SSID);
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGI(TAG, "Connected! IP: %s", s_ip_str);
    return ESP_OK;
}

const char* wifi_get_ip_str(void)
{
    return s_ip_str;
}

esp_err_t wifi_scan_once(uint16_t* out_count, wifi_ap_record_t** out_info)
{
    // Ensure Wi-Fi is in STA mode
    ESP_ERROR_CHECK(esp_wifi_disconnect());
    wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,        // 0 = all channels
        .show_hidden = true
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Start scan (blocking)
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));

    uint16_t num_ap = 0;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&num_ap));
    *out_count = num_ap;
    *out_info = malloc(sizeof(wifi_ap_record_t) * num_ap);
    if (*out_info == NULL) {
        return ESP_ERR_NO_MEM;
    }
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(out_count, *out_info));
    return ESP_OK;
}
