#include "../include/include.h"

// Global variables
QueueHandle_t packet_queue;
static bool led_state = false;
static int timer_quant = 0;
static int last_timer_val = 0;
static state_t current_state = STATE_WAIT;

#define TIMER_TO_MS(x) ((x) / portTICK_PERIOD_MS)


static void state_change(state_t new_state) {
  // Change the state of the device
  if (new_state == STATE_LISTENER) {
    Serial.println("Switching to LISTENER mode");
    led_state = false;
  } else if (new_state == STATE_WRITER) {
    Serial.println("Switching to WRITER mode");
    led_state = true;
  }
}

static void reset_timer() {
  // Reset the timer
  timer_quant = 0;
  last_timer_val = 0;
  Serial.println("Timer reset");
}


static void task_runner() {
  int current_time_ms = TIMER_TO_MS(xTaskGetTickCount());
  int diff = current_time_ms - last_timer_val;
  
  timer_quant += diff;
  
}

static void run_writer_task() {
  
}

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
