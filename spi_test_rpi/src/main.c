// Slave as a transmitter for SPI communitation

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"
#include "lwip/igmp.h"

#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "soc/rtc_periph.h"
#include "driver/spi_slave.h"
#include "esp_log.h"
#include "spi_flash_mmap.h"
#include "driver/gpio.h"
#include "driver/uart.h"


#define GPIO_MOSI 23
#define GPIO_MISO 19
#define GPIO_SCLK 18
#define GPIO_CS 5

static const char *TAG = "SPI_Slave_Receiver_Test";

void app_main(void)
{
    printf("ESP32 SPI Slave Transmitter Test\n");

    spi_bus_config_t buscfg={
        .mosi_io_num=GPIO_MOSI,
        .miso_io_num=GPIO_MISO,
        .sclk_io_num=GPIO_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };

    spi_slave_interface_config_t slvcfg={
        .mode=0,
        .spics_io_num=GPIO_CS,
        .queue_size=1,
        .flags=0,
        .post_setup_cb=NULL,
        .post_trans_cb=NULL
    };

    gpio_set_pull_mode(GPIO_MOSI, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_SCLK, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_CS, GPIO_PULLUP_ONLY);

    esp_err_t ret;
    ret = spi_slave_initialize(VSPI_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize SPI slave (VSPI): %s", esp_err_to_name(ret));
        return;
    } else {
        ESP_LOGI(TAG, "VSPI Slave Initialized Successfully");
    }

    WORD_ALIGNED_ATTR uint8_t recvbuf[4] = {0}; // Small buffer for 1 byte + alignment
    WORD_ALIGNED_ATTR uint8_t sendbuf[4] = {'H', 'e', 'l', 'p'}; // Send 'H' as first byte
    spi_slave_transaction_t t;

    while (1)
    {
        // Clear buffers
        memset(recvbuf, 0, sizeof(recvbuf));
        memset(&t, 0, sizeof(t));
        
        // Prepare transaction for exactly 1 byte
        t.length = 4 * 8; // 1 byte = 8 bits
        t.rx_buffer = recvbuf;
        t.tx_buffer = sendbuf;

        // Wait for the master to initiate transaction
        // ESP_LOGI(TAG, "Waiting for 1-byte transaction...");
        ret = spi_slave_transmit(VSPI_HOST, &t, portMAX_DELAY);
        
        if (ret == ESP_OK) {
            ESP_LOGI(TAG, "Transaction completed. Bytes received: %d", t.trans_len / 8);
            ESP_LOGI(TAG, "Sent: 0x%02X 0x%02X 0x%02X 0x%02X ('%c%c%c%c')", sendbuf[0], sendbuf[1], sendbuf[2], sendbuf[3], sendbuf[0], sendbuf[1], sendbuf[2], sendbuf[3]);
            if (t.trans_len > 0) {
                ESP_LOGI(TAG, "Received: 0x%02X 0x%02X 0x%02X 0x%02X ('%c%c%c%c')", recvbuf[0], recvbuf[1], recvbuf[2], recvbuf[3], recvbuf[0], recvbuf[1], recvbuf[2], recvbuf[3]);
            }
        } else {
            ESP_LOGE(TAG, "SPI slave transaction failed: %s", esp_err_to_name(ret));
        }
    }
}
