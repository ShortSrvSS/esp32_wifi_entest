#pragma once
#include "esp_err.h"
#include "esp_wifi.h"

/**
 * @brief Initialize Wi-Fi as STA using CONFIG_WIFI_SSID / CONFIG_WIFI_PASSWORD.
 *        Blocks until an IP is obtained or times out.
 */
esp_err_t wifi_init_sta(void);

/**
 * @brief Return the IP address assigned to ESP32 in STA mode as a C string.
 *        (e.g. "192.168.1.123")
 */
const char* wifi_get_ip_str(void);

/**
 * @brief Perform a one-shot scan of nearby APs.
 * @param[out] out_count  Number of APs found.
 * @param[out] out_info   Dynamically malloc’d array of wifi_ap_record_t. Caller must free().
 */
esp_err_t wifi_scan_once(uint16_t* out_count, wifi_ap_record_t** out_info);
