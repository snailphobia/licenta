#ifndef SPI_PROTOCOL_INCL_H
#define SPI_PROTOCOL_INCL_H

#include "include.h" // Assuming this brings in necessary types like gpio_num_t, esp_err_t from Arduino ESP32 framework

// Protocol Constants
#define SPI_MAGIC           0x69
#define SPI_MAX_PAYLOAD     MTU
#define SPI_HEADER_SIZE     16
#define SPI_MAX_PACKET      (SPI_HEADER_SIZE + SPI_MAX_PAYLOAD)

#define ESP32C3MINI

#ifdef ESP32WROOM

#define GPIO_MOSI         GPIO_NUM_23  // SPI MOSI pin
#define GPIO_MISO         GPIO_NUM_19  // SPI MISO pin
#define GPIO_SCLK         GPIO_NUM_18  // SPI SCLK pin
#define GPIO_CS           GPIO_NUM_5   // SPI CS pin

#endif

#ifdef ESP32C3MINI

#define VSPI_HOST    SPI2_HOST // Use SPI2 for ESP32-C3 Mini

// #define GPIO_MOSI           GPIO_NUM_6  // SPI MOSI pin
// #define GPIO_MISO           GPIO_NUM_5  // SPI MISO pin
// #define GPIO_SCLK           GPIO_NUM_4  // SPI SCLK pin
// #define GPIO_CS             GPIO_NUM_7  // SPI CS pin
#define GPIO_MOSI           GPIO_NUM_7  // SPI MOSI pin
#define GPIO_SCLK           GPIO_NUM_6  // SPI SCLK pin
#define GPIO_MISO           GPIO_NUM_5  // SPI MISO pin
#define GPIO_CS             GPIO_NUM_4  // SPI CS pin

#define GPIO_SIG            GPIO_NUM_10 // signal pin for spi ready

#endif

// Packet Types
typedef enum {
    
    MASTER_CONTINUE_DATA = 0x00, // continue sending data
    MASTER_START_DATA = 0x01, // start sending data
    MASTER_END_DATA = 0x02, // end sending data
    SPI_START_PKT = 0x10,
    SPI_END_PKT = 0x11,
    SPI_DATA_PKT = 0x12,
    MASTER_ACK = 0x20,
    SPI_SSTAT = 0x30,
} spi_packet_type_t;

// Packet Structure
typedef struct __attribute__((packed)) {
    uint8_t magic;              // Magic byte for validation
    uint8_t type;               // Packet type
    uint8_t seq;                // Sequence number
    uint8_t payload_len;        // Payload length
    struct {
        uint8_t channel; // Channel number
        uint8_t device_id; // Device ID in SPI line
        uint16_t wifi_packet_length; // Length of the SPI packet
    } id;
    struct {
        uint32_t ts_sec; // Timestamp seconds
        uint32_t ts_usec; // Timestamp microseconds
    } time;
    uint8_t payload[SPI_MAX_PAYLOAD]; // exclusively for wifi packets
} spi_packet_t;

// Public API Function declarations

/**
 * @brief Creates a SPI packet with the given data, size, sequence number, type, and checksum.
 * This function initializes a spi_packet_t structure with the provided parameters.
 * @param data Pointer to the data to be included in the packet.
 * @param size Size of the data to be included in the packet.
 * @param seq Sequence number for the packet.
 * @param type Type of the packet (e.g., MASTER_CONTINUE_DATA, SPI_START_PKT).
 * @param channel Channel number for the packet.
 * @param device_id Device ID of the SPI slave.
 * @return spi_packet_t The created SPI packet.
 */
spi_packet_t create_packet(const char *data, int size, uint8_t seq, uint8_t type, uint8_t channel, uint8_t device_id);

/**
 * @brief Initializes the SPI protocol slave.
 * This must be called before any other SPI protocol functions.
 * The underlying implementation uses ESP-IDF SPI drivers.
 * 
 * @param mosi GPIO number for MOSI
 * @param miso GPIO number for MISO
 * @param sclk GPIO number for SCLK
 * @param cs   GPIO number for CS
 * @return esp_err_t ESP_OK on success, or an error code on failure.
 */
esp_err_t spi_protocol_init(gpio_num_t mosi, gpio_num_t miso, gpio_num_t sclk, gpio_num_t cs);

/**
 * @brief Deinitializes the SPI protocol slave and frees resources.
 */
void spi_protocol_deinit(void);

/**
 * @brief Adds a data packet to the SPI write queue to be sent to the master.
 * The data should be a spi_packet_t structure, which includes the specific header.
 * If the queue is full, the oldest packet will be dropped to make space.
 * 
 * @param data Pointer to the byte array containing the data to send.
 * @return true if the packet was successfully added or made space for, false otherwise.
 */
bool spi_add_packet(spi_packet_t *data);

/**
 * @brief Reads a data packet received from the master from the SPI read queue.
 * The provided data buffer should be at least SPI_MAX_PACKET size.
 * 
 * @param data Pointer to a packet structure where the received data will be stored.
 * @return true if a packet was successfully read, false if the read queue was empty.
 */
bool spi_read_packet(spi_packet_t *data);

/**
 * @brief Get the contents of an internal SPI buffer (recvbuf or sendbuf).
 * Note: Use with caution, primarily for debugging or specific advanced scenarios.
 * Prefer using spi_add_packet and spi_read_packet for standard data transfer.
 * 
 * @param which_buffer 0 for recvbuf (intended for received data from master), 1 for sendbuf (data to be sent to master).
 * @return const char* Pointer to the internal buffer, or NULL if an error occurs. The buffer content might change with SPI transactions.
 */
const char *get_buf(int which_buffer);

/**
 * @brief Set the contents of the internal SPI send buffer.
 * Note: Use with caution, primarily for debugging or specific advanced scenarios.
 * Prefer using spi_add_packet for queueing data to be sent.
 * 
 * @param data Pointer to the data to copy into the send buffer. Data is copied up to SPI_MAX_PACKET bytes.
 */
void set_buf(const char *data);

/**
 * @brief Get the number of packets currently in the SPI write queue.
 * This function may be useful for congwifi snifferstion control or monitoring purposes
 */
int spi_get_write_queue_count(void);


/**
 * @brief Feeds the send buffer with the next packet to be sent.
 * This function should be called periodically to ensure that the SPI send buffer is filled
 * with packets to be sent to the master device.
 * 
 * @return true if a packet was successfully added to the send buffer, false if no packets were available.
 */
bool feed_send_buffer(void);

/**
 * @brief Attempts to perform a transaction with the SPI master.
 * This function should be called periodically to process incoming packets from the master
 * and send outgoing packets to the master.
 * 
 * @return true if a transaction was successfully performed, false if the transaction timed out 
 * or failed due to other reasons.
 */
bool attempt_transaction(int timeout_ms);

void spi_transaction_task(void *pvParameters);

#endif // SPI_PROTOCOL_INCL_H