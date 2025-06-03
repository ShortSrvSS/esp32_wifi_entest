#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize a new PCAP file at the given path.
 *        Writes the global PCAP header.
 * @param filename Absolute path (e.g., "/spiffs/handshake.pcap")
 * @return true on success, false on failure.
 */
bool pcap_writer_init(const char* filename);

/**
 * @brief Append a single 802.11 packet (raw bytes) to the PCAP file.
 * @param data   Pointer to raw 802.11 frame (header + payload).
 * @param length Length of data in bytes.
 * @return true on success, false on failure.
 */
bool pcap_writer_write_packet(const uint8_t* data, uint32_t length);

/**
 * @brief Close the PCAP file (flush and fclose).
 */
void pcap_writer_close(void);

#ifdef __cplusplus
}
#endif
