#include "../include/include.h"

// Global variables
QueueHandle_t packet_queue;
static bool led_state = false;

void setup() {
  // Initialize serial for debugging
  Serial.begin(115200);
  delay(500); // Allow serial to initialize
  
  Serial.println("\n\nESP32 WiFi Sniffer - Slave Node");
  Serial.printf("Node ID: %d\n", DEVICE_ID);

//   // Initialize NVS
//   esp_err_t ret = nvs_flash_init();
//   if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
//     ESP_ERROR_CHECK(nvs_flash_erase());
//     ret = nvs_flash_init();
//   }
//   ESP_ERROR_CHECK(ret);

//   // Create mutex for buffer access
//   buffer_mutex = xSemaphoreCreateMutex();
//   if (buffer_mutex == NULL) {
//     Serial.println("Failed to create buffer mutex");
//   }

//   // Create the packet queue
//   packet_queue = xQueueCreate(QUEUE_SIZE, sizeof(wifi_packet_t));
//   if (packet_queue == NULL) {
//     Serial.println("Failed to create packet queue");
//   }
  
//   // Calculate slave address from base address and device ID
//   uint8_t slave_addr = I2C_BASE_ADDR + DEVICE_ID;
//   if (DEVICE_ID < 1 || DEVICE_ID > 127) {
//     Serial.println("ERROR: Invalid DEVICE_ID. Must be between 1 and 127.");
//   }
  
//   i2c_slave_init(slave_addr);
//   wifi_sniffer_init();
//   xTaskCreate(
//     packet_processing_task,
//     "packet_proc",
//     8192,
//     NULL,
//     1,
//     NULL
//   );
  
//   Serial.println("Setup complete, WiFi packet monitoring active");

}

void loop() {
    
}
