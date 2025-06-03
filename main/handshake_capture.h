#pragma once
#include "esp_err.h"
#include <stdint.h>

/**
 * @brief Perform a 20 s deauth + handshake capture on the target AP.
 * 
 * @param bssid   6-byte MAC of the target AP.
 * @param channel Channel number (1‒13).
 * @param duration_ms Total time (ms) to send deauth + capture.
 * @return ESP_OK on success, error otherwise.
 *
 * After this returns, /spiffs/handshake.pcap contains any captured 4-way EAPOL packets.
 */
esp_err_t handshake_deauth_and_capture(const uint8_t bssid[6], uint8_t channel, uint32_t duration_ms);
