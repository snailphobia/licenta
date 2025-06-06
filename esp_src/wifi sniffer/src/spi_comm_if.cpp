#include "../include/spi_protocol_incl.h"
#include "esp_heap_caps.h"

static const char *TAG = "ESP_SPI_PROTOCOL";

static char *recvbuf = NULL, *sendbuf = NULL;
char *queue_buffer = NULL; int queue_buffer_size = 0;

spi_packet_t create_packet(const char *data, int size, uint8_t seq, uint8_t type, uint32_t checksum) {
    spi_packet_t packet = {0};
    packet.magic = SPI_MAGIC;
    packet.type = type;
    packet.seq = seq;
    packet.payload_len = size;
    packet.checksum = checksum;
    if (data && size > 0 && size <= SPI_MAX_PAYLOAD) {
        memcpy(packet.payload, data, size);
    } else {
        ESP_LOGE(TAG, "Invalid data or size for packet creation");
    }
    return packet;
}

esp_err_t spi_protocol_init(gpio_num_t mosi, gpio_num_t miso, gpio_num_t sclk, gpio_num_t cs) {
    spi_bus_config_t buscfg = {
        .mosi_io_num = mosi,
        .miso_io_num = miso,
        .sclk_io_num = sclk,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = SPI_MAX_PACKET
    };

    spi_slave_interface_config_t slvcfg = {
        .spics_io_num = cs,
        .flags = 0,
        .queue_size = 10,
        .mode = 0,
        .post_setup_cb = NULL,
        .post_trans_cb = NULL
    };

    gpio_set_pull_mode(GPIO_SCLK, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_CS, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(GPIO_MOSI, (gpio_pull_mode_t)GPIO_PULLUP_ENABLE);
    gpio_set_pull_mode(GPIO_MISO, (gpio_pull_mode_t)GPIO_PULLUP_ENABLE);

    esp_err_t ret = spi_slave_initialize(VSPI_HOST, &buscfg, &slvcfg, 1);
    if (ret != ESP_OK) ESP_LOGE(TAG, "Failed to initialize SPI slave in VSPI mode: %s", esp_err_to_name(ret));

    recvbuf = (char*)heap_caps_malloc(SPI_MAX_PACKET, MALLOC_CAP_DMA | MALLOC_CAP_8BIT),
    sendbuf = (char*)heap_caps_malloc(SPI_MAX_PACKET, MALLOC_CAP_DMA | MALLOC_CAP_8BIT);
    
    queue_buffer = (char *)calloc(SPI_MAX_PACKET, 100);

    if (!recvbuf || !sendbuf) ESP_LOGI(TAG, "Failed to initiate buffers\n");
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
    if (queue_buffer_size > 100) {
        ESP_LOGW(TAG, "Queue buffer is full, dropping oldest packet");
        // Shift the queue_buffer to make space for the new packet
        memmove(queue_buffer, queue_buffer + SPI_MAX_PACKET, (100 - 1) * SPI_MAX_PACKET);
        queue_buffer_size--;
    }
    if (data) {
        memcpy(queue_buffer + (queue_buffer_size * SPI_MAX_PACKET), data, SPI_MAX_PACKET);
        queue_buffer_size++;
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
            spi_packet_t spi_packet = create_packet(packet, packet_size, i, SPI_DATA_PKT, 0); // Assuming checksum is 0 for simplicity
            spi_add_packet(&spi_packet);
        }
    }
    ESP_LOGI(TAG, "Split buffer into %d SPI packets", packets_count);
}

int spi_get_write_queue_count(void) {
    return queue_buffer_size;
}
