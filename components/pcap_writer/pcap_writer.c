/**
 * pcap_writer.c
 *
 * Minimal PCAP writer for ESP32 using standard fopen/fwrite on SPIFFS.
 */

#include "pcap_writer.h"
#include "esp_log.h"
#include <string.h>
#include <sys/time.h>

// PCAP Global Header (24 bytes)
typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;   // GMT offset
    uint32_t sigfigs;    // accuracy of timestamps
    uint32_t snaplen;    // max length of captured packets, in bytes
    uint32_t network;    // data link type (LINKTYPE_IEEE802_11)
} pcap_global_header_t;

// Per-packet header (16 bytes)
typedef struct {
    uint32_t ts_sec;     // timestamp seconds
    uint32_t ts_usec;    // timestamp microseconds
    uint32_t incl_len;   // number of bytes of packet saved in file
    uint32_t orig_len;   // actual length of packet
} pcap_packet_header_t;

static const char* TAG = "pcap_writer";
static FILE* pcap_file = NULL;

bool pcap_writer_init(const char* filename)
{
    // Open for writing (binary), truncating if exists
    pcap_file = fopen(filename, "wb");
    if (!pcap_file) {
        ESP_LOGE(TAG, "Failed to fopen(%s)", filename);
        return false;
    }

    pcap_global_header_t gh = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 0x0000ffff,    // max packet length
        .network = 105            // LINKTYPE_IEEE802_11
    };

    size_t w = fwrite(&gh, sizeof(gh), 1, pcap_file);
    if (w != 1) {
        ESP_LOGE(TAG, "Write PCAP global header failed");
        fclose(pcap_file);
        pcap_file = NULL;
        return false;
    }
    ESP_LOGI(TAG, "PCAP file initialized: %s", filename);
    return true;
}

bool pcap_writer_write_packet(const uint8_t* data, uint32_t length)
{
    if (!pcap_file) {
        return false;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);

    pcap_packet_header_t ph = {
        .ts_sec = tv.tv_sec,
        .ts_usec = tv.tv_usec,
        .incl_len = length,
        .orig_len = length
    };

    if (fwrite(&ph, sizeof(ph), 1, pcap_file) != 1) {
        ESP_LOGE(TAG, "Failed to write packet header");
        return false;
    }
    if (fwrite(data, length, 1, pcap_file) != 1) {
        ESP_LOGE(TAG, "Failed to write packet data");
        return false;
    }
    return true;
}

void pcap_writer_close(void)
{
    if (pcap_file) {
        fclose(pcap_file);
        pcap_file = NULL;
        ESP_LOGI(TAG, "PCAP file closed");
    }
}
