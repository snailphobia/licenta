#include "../include/include.h"

static uint8_t buffer[MTU]; 
static uint16_t buffer_len = 0;
SemaphoreHandle_t buffer_mutex = NULL;
static uint8_t last_command = 0;

void i2c_slave_init(uint8_t address) {
  Wire.begin((int)address, I2C_SLAVE_SDA, I2C_SLAVE_SCL, I2C_FREQ);
  Wire.onRequest(i2c_request_handler);
  Wire.onReceive(i2c_receive_handler);
  Serial.printf("I2C initialized in slave mode (address: 0x%02X)\n", address);
}

void i2c_request_handler() {
  if (last_command == CMD_STATUS_REQ) {
    // Send status information (current channel, packet count)
    uint8_t status_data[5];
    uint8_t current_channel = WIFI_CHANNEL;
    
    status_data[0] = current_channel;
    status_data[1] = (packet_count >> 24) & 0xFF;
    status_data[2] = (packet_count >> 16) & 0xFF;
    status_data[3] = (packet_count >> 8) & 0xFF;
    status_data[4] = packet_count & 0xFF;
    
    Wire.write(status_data, 5);
  }
  else if (last_command == CMD_DATA_REQ) {
    if (xSemaphoreTake(buffer_mutex, portMAX_DELAY) == pdTRUE) {
      if (buffer_len > 0) {
        uint16_t send_len = (buffer_len > MAX_I2C_PACKET) ? MAX_I2C_PACKET : buffer_len;
        Wire.write(buffer, send_len);

        if (send_len < buffer_len) {
          memmove(buffer, buffer + send_len, buffer_len - send_len);
          buffer_len -= send_len;
        } else {
          buffer_len = 0;
        }
      } else {
        Wire.write(0);
      }
      xSemaphoreGive(buffer_mutex);
    }

  }
}

void i2c_receive_handler(int byte_count) {
  if (byte_count > 0) {
    uint8_t command = Wire.read();
    byte_count--;

    last_command = command;
    
    switch (command) {
      case CMD_CHANNEL_SET:
        if (byte_count > 0) {
          uint8_t new_channel = Wire.read();
          if (new_channel >= 1 && new_channel <= 13) {
            wifi_sniffer_set_channel(new_channel);
          }
        }
        break;
      
      default:
        while (byte_count--) {
          Wire.read();
        }
        break;
    }
  }
}

void store_packet_to_buffer(wifi_packet_t *pkt) {
  if (xSemaphoreTake(buffer_mutex, portMAX_DELAY) == pdTRUE) {
    buffer_len = pkt->length > MTU ? MTU : pkt->length;
    memcpy(buffer, pkt->payload, buffer_len);
    
    xSemaphoreGive(buffer_mutex);
  }
}