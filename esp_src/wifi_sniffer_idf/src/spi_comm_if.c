#include "../include/spi_protocol_incl.h"
#include "esp_heap_caps.h"

static const char *TAG = "ESP_SPI_PROTOCOL";

char *recvbuf = NULL, *sendbuf = NULL;
char *queue_buffer = NULL; int queue_buffer_size = 0;
bool send_buffer_ready = false;
static spi_bus_config_t main_buscfg = {0};
static spi_slave_interface_config_t main_slvcfg = {0};

spi_packet_t create_packet(const char *data, int size, uint8_t seq, uint8_t type, uint8_t channel, uint8_t device_id) {
    spi_packet_t packet = {0};
    packet.magic = SPI_MAGIC;
    packet.type = type;
    packet.seq = seq;
    packet.payload_len = size;
    packet.id.channel = channel;
    packet.id.device_id = device_id;
    packet.id.wifi_packet_length = (uint16_t)size;
    if (data && size > 0 && size <= SPI_MAX_PAYLOAD) {
        memcpy(packet.payload, data, size);
    } else {
        ESP_LOGE(TAG, "Invalid data or size for packet creation");
    }
    return packet;
}

bool attempt_transaction(int timeout_ms) {
    if (!recvbuf || !sendbuf) {
        ESP_LOGE(TAG, "Buffers are not initialized");
        return false;
    }

    spi_slave_transaction_t spi_transaction = {};
    spi_transaction.length = SPI_MAX_PACKET * 8;
    spi_transaction.rx_buffer = recvbuf;
    spi_transaction.tx_buffer = sendbuf;
    ESP_LOGI("SENDING", "Attempting SPI transaction with timeout %d ms, with buffer %02X%02X%02X%02X%02X%02X...", timeout_ms,
             sendbuf[0], sendbuf[1], sendbuf[2],
             sendbuf[3], sendbuf[4], sendbuf[5]);
    // wait for timeout ms
    // esp_err_t ret = spi_slave_transmit(VSPI_HOST, &spi_transaction, portMAX_DELAY);
    esp_err_t ret = spi_slave_transmit(VSPI_HOST, &spi_transaction, timeout_ms / portTICK_PERIOD_MS);
    // if the transaction timed out, return false, else return true
    if (ret == ESP_ERR_TIMEOUT) {
        ESP_LOGW(TAG, "SPI transaction timed out");
        return false;
    } else if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPI transaction failed: %s", esp_err_to_name(ret));
        return false;
    }
    send_buffer_ready = false;
    return true;
}


bool feed_send_buffer(void) {
    // print the first 6 packets in the send_buffer
    // Serial.printf("Queue buffer size: %d; send buffer ready: %s\n",
    //               queue_buffer_size, send_buffer_ready ? "true" : "false");
    // Serial.printf("%02X%02X%02X%02X%02X%02X\n",
    //     sendbuf[0], sendbuf[1], sendbuf[2],
    //     sendbuf[3], sendbuf[4], sendbuf[5]);
    // printf("Queue buffer size: %d; send buffer ready: %s\n",
    //        queue_buffer_size, send_buffer_ready ? "true" : "false");
    // printf("%02X %02X %02X %02X %02X %02X\n",
    //        sendbuf[0], sendbuf[1], sendbuf[2],
    //        sendbuf[3], sendbuf[4], sendbuf[5]);
    if (send_buffer_ready) {
        // ESP_LOGE(TAG, "Send buffer is NULL or already ready");
        return false;
    }
    
    if (queue_buffer_size == 0) {
        ESP_LOGW(TAG, "No packets to send, send buffer remains empty");
        return false;
    }

    // Copy the first packet from queue_buffer to sendbuf
    memcpy(sendbuf, queue_buffer, SPI_MAX_PACKET);
    queue_buffer_size--;
    
    // Shift the queue_buffer to remove the sent packet
    memmove(queue_buffer, queue_buffer + SPI_MAX_PACKET, queue_buffer_size * SPI_MAX_PACKET);
    send_buffer_ready = true;

    ESP_LOGI(TAG, "Send buffer prepared with packet, size now: %d", queue_buffer_size);
    return true;
}

void spi_transaction_task(void *pvParameters) {
    TickType_t last_wake_time;
    const TickType_t xFrequency = pdMS_TO_TICKS(100);
    const TickType_t xProcessingDuration = pdMS_TO_TICKS(10);

    
    last_wake_time = xTaskGetTickCount();
    for (;;) {
        // vTaskDelayUntil(&last_wake_time, xFrequency);

        TickType_t xProcessingStartTime = xTaskGetTickCount();
        ESP_LOGI("DEBUG1", "Starting SPI transaction task at %lu ms", xProcessingStartTime * portTICK_PERIOD_MS);
        while ((xTaskGetTickCount() - xProcessingStartTime) < xProcessingDuration) {
            ESP_LOGW(TAG, "Processing SPI transaction...");
            feed_send_buffer();
            if (!attempt_transaction(0)) {
                ESP_LOGW(TAG, "Transaction failed, retrying...");
            } else {
                ESP_LOGI(TAG, "Transaction successful");
            }
            vTaskDelay(pdMS_TO_TICKS(1));
        }
        ESP_LOGI("DEBUG2", "SPI transaction task processing cycle completed at %lu ms",
                 xTaskGetTickCount() * portTICK_PERIOD_MS);
        // Serial.println("SPI transaction task completed processing cycle");
        // printf("SPI transaction task completed processing cycle at %lu ms\n", xTaskGetTickCount() * portTICK_PERIOD_MS);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    //delay(100);
}

esp_err_t spi_protocol_init(gpio_num_t mosi, gpio_num_t miso, gpio_num_t sclk, gpio_num_t cs) {
    spi_bus_config_t buscfg = {
        .mosi_io_num = mosi,
        .miso_io_num = miso,
        .sclk_io_num = sclk,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 0,
    };

    spi_slave_interface_config_t slvcfg = {
        .spics_io_num = cs,
        .flags = 0,
        .queue_size = 3,
        .mode = 0,
        .post_setup_cb = NULL,
        .post_trans_cb = NULL,
    };

    main_buscfg = buscfg; main_slvcfg = slvcfg;

    // set GPIO_SIG as output


    // gpio_set_pull_mode(GPIO_CS, GPIO_PULLUP_ENABLE);
    // gpio_set_pull_mode(GPIO_MOSI, GPIO_PULLDOWN_ONLY);
    // gpio_set_pull_mode(GPIO_MISO, GPIO_PULLDOWN_ONLY);

    esp_err_t ret = spi_slave_initialize(VSPI_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "spi_slave_initialize failed: %s", esp_err_to_name(ret));
        return ret;

    }

    recvbuf = (char*)heap_caps_malloc(SPI_MAX_PACKET,
                                        MALLOC_CAP_DMA);
    sendbuf = (char*)heap_caps_malloc(SPI_MAX_PACKET,
                                        MALLOC_CAP_DMA);
    queue_buffer = (char*)calloc(10, SPI_MAX_PACKET);

    if (!recvbuf || !sendbuf || !queue_buffer) {
        ESP_LOGE(TAG,
                "Out of memory: recv=%p send=%p queue=%p",
                recvbuf, sendbuf, queue_buffer);
        if (recvbuf)       heap_caps_free(recvbuf);
        if (sendbuf)       heap_caps_free(sendbuf);
        if (queue_buffer)  free(queue_buffer);
        return ESP_ERR_NO_MEM;
    }

    memset(recvbuf,      0, SPI_MAX_PACKET);
    memset(sendbuf,      0, SPI_MAX_PACKET);
    memset(queue_buffer, 0, SPI_MAX_PACKET * 10);

    ESP_LOGI(TAG,
            "SPI init OK — recvbuf=%p sendbuf=%p queuebuf=%p",
            recvbuf, sendbuf, queue_buffer);
    return ESP_OK;
}

void spi_protocol_deinit(void) {
    // close connection and free memory
    if (recvbuf) {
        heap_caps_free(recvbuf);
        recvbuf = NULL;
    } else {
        ESP_LOGE(TAG, "recvbuf is already NULL");
    }

    if (sendbuf) {
        heap_caps_free(sendbuf);
        sendbuf = NULL;
    } else {
        ESP_LOGE(TAG, "sendbuf is already NULL");
    }
    esp_err_t ret = spi_slave_free(VSPI_HOST);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to free SPI slave: %s", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "SPI slave freed successfully");
    }
}

bool spi_add_packet(spi_packet_t *data) {
    if (queue_buffer_size > 10) {
        ESP_LOGW(TAG, "Queue buffer is full, dropping oldest packet");
        // Shift the queue_buffer to make space for the new packet
        memmove(queue_buffer, queue_buffer + SPI_MAX_PACKET, (10 - 1) * SPI_MAX_PACKET);
        queue_buffer_size--;
    }
    if (data) {
        memcpy(queue_buffer + (queue_buffer_size * SPI_MAX_PACKET), data, SPI_MAX_PACKET);
        queue_buffer_size++;

        ESP_LOGI(TAG, "DEBUG: Packet starts with: %02X %02X %02X %02X %02X %02X",
                 data->payload[0], data->payload[1], data->payload[2],
                 data->payload[3], data->payload[4], data->payload[5]);
        return true;
    } else {
        ESP_LOGE(TAG, "Data is NULL, cannot add packet");
        return false;
    }
}

bool spi_read_packet(spi_packet_t* data) {
    if (queue_buffer_size == 0) {
        ESP_LOGW(TAG, "Read queue is empty, nothing to read");
        return false;
    }
    if (data) {
        memcpy(data, queue_buffer, SPI_MAX_PACKET);
        // Shift the queue_buffer to remove the read packet
        memmove(queue_buffer, queue_buffer + SPI_MAX_PACKET, (queue_buffer_size - 1) * SPI_MAX_PACKET);
        queue_buffer_size--;
        return true;
    } else {
        ESP_LOGE(TAG, "Data buffer is NULL, cannot read packet");
        return false;
    }
}


const char *get_buf(int which_buffer) {
    if (which_buffer == 0) {
        if (recvbuf) {
            return recvbuf;
        } else {
            ESP_LOGE(TAG, "recvbuf is NULL");
            return NULL;
        }
    } else {
        if (sendbuf) {
            return sendbuf;
        } else {
            ESP_LOGE(TAG, "sendbuf is NULL");
            return NULL;
        }
    }
    return "";
}

void set_buf(const char *buf) {
    if (sendbuf && buf) {
        memcpy(sendbuf, buf, SPI_MAX_PACKET);
    } else {
        ESP_LOGE(TAG, "sendbuf is NULL or buf is NULL");
    }
}

void split_buffer_into_spi_packets(const char *buffer, int buffer_size) {
    if (buffer_size <= 0 || buffer == NULL) {
        ESP_LOGE(TAG, "Invalid buffer or buffer size");
        return;
    }

    int packets_count = (buffer_size + SPI_MAX_PAYLOAD - 1) / SPI_MAX_PAYLOAD; // Calculate number of packets needed
    for (int i = 0; i < packets_count; i++) {
        int offset = i * SPI_MAX_PACKET;
        int packet_size = (i == packets_count - 1) ? (buffer_size % SPI_MAX_PACKET) : SPI_MAX_PACKET;

        if (packet_size > 0) {
            char packet[SPI_MAX_PACKET] = {0};
            memcpy(packet, buffer + offset, packet_size);
            spi_packet_t spi_packet = create_packet(packet, packet_size, i, SPI_DATA_PKT, 
                                                    WIFI_CHANNEL, DEVICE_ID);
            spi_add_packet(&spi_packet);
        }
    }
    ESP_LOGI(TAG, "Split buffer into %d SPI packets", packets_count);
}

int spi_get_write_queue_count(void) {
    return queue_buffer_size;
}
