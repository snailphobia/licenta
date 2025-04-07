#ifndef INCLUDE_H
#define INCLUDE_H

#include <Arduino.h>
#include <WiFi.h>
#include <Wire.h>
#include <SPIFFS.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#define MTU                 1500
#define QUEUE_SIZE          100

#define DEVICE_ID           0       // 0=master, 1-127=slave ID
#define WIFI_CHANNEL        1       // Channel this node will monitor (ignored on master)
#define I2C_MASTER_SDA      21      // I2C SDA pin (master only)
#define I2C_MASTER_SCL      22      // I2C SCL pin (master only)
#define I2C_SLAVE_SDA       21      // I2C SDA pin (slaves only)
#define I2C_SLAVE_SCL       22      // I2C SCL pin (slaves only)
#define I2C_FREQ            200000  // I2C frequency (200kHz)
#define I2C_BASE_ADDR       0x64

#define CMD_CHANNEL_SET     0x01
#define CMD_STATUS_REQ      0x02
#define CMD_DATA_REQ        0x03
#define MAX_I2C_PACKET      32

typedef struct {
    uint32_t magic_number;   // magic number
    uint16_t version_major;  // major version number
    uint16_t version_minor;  // minor version number
    int32_t  thiszone;       // GMT to local correction
    uint32_t sigfigs;        // accuracy of timestamps
    uint32_t snaplen;        // max length of captured packets
    uint32_t network;        // data link type
} pcap_file_header_t;

typedef struct {
    uint32_t ts_sec;         // timestamp seconds
    uint32_t ts_usec;        // timestamp microseconds
    uint32_t incl_len;       // number of octets of packet saved in file
    uint32_t orig_len;       // actual length of packet
} pcap_packet_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint16_t length;
    uint8_t payload[MTU];
} wifi_packet_t;

/**
 * extern globals for sharing across files
 */
extern QueueHandle_t packet_queue;
extern SemaphoreHandle_t buffer_mutex;
extern uint32_t packet_count;

/**
 * Functions defined in src/ch_monitor.cpp
 */
void wifi_sniffer_init(void);
void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
void wifi_sniffer_set_channel(uint8_t channel);
void packet_processing_task(void *pvParameter);
uint8_t wifi_sniffer_get_channel(void);

// logging functions
void packet_writer_task(void *pvParameter);
void initialize_pcap_file(void);

/**
 * Functions defined in i2c_line_comms.cpp
 */
void i2c_init(uint8_t address);
void i2c_request_handler(void);
void i2c_receive_handler(int byte_count);
void store_packet_to_buffer(wifi_packet_t *pkt);
void send_packet_to_master(wifi_packet_t *pkt);

#endif // INCLUDE_H