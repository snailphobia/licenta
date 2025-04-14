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
    current_state = STATE_LISTENER;
    led_state = true;
  } else if (new_state == STATE_WRITER) {
    Serial.println("Switching to WRITER mode");
    current_state = STATE_WRITER;
    led_state = false;
  }
}

#ifdef MONITOR

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
  if (timer_quant > MAX_QUANT) {
    reset_timer();
    state_change(current_state == STATE_LISTENER ? STATE_WRITER : STATE_LISTENER);
    // todo: add communication method to allow master to control state changes if needed
  } else {
    last_timer_val = current_time_ms;
    if (current_state == STATE_LISTENER) run_listener_task();
    else if (current_state == STATE_WRITER) run_writer_task();
  }
  
}

static void run_writer_task() {
  // Run the writer task
  if (xSemaphoreTake(buffer_mutex, portMAX_DELAY) == pdTRUE) {
    wifi_packet_t pkt;
    if (xQueueReceive(packet_queue, &pkt, 0) == pdTRUE) {
      // Process the packet
      Serial.printf("Processing packet of length %d\n", pkt.length);
      // Add your packet processing logic here
    }
    xSemaphoreGive(buffer_mutex);
  }
}

static void run_listener_task() {
  wifi_packet_t pkt;
  if (xQueueReceive(packet_queue, &pkt, pdMS_TO_TICKS(5)) == pdTRUE) {
    // Process the packet
    Serial.printf("Processing packet of length %d\n", pkt.length);
    // Add your packet processing logic here
  }
}

#endif

#ifdef COMM

#endif 

void setup() {
  // Initialize serial for debugging
  Serial.begin(115200);
  delay(500); // Allow serial to initialize
  
#ifdef MONITOR

  Serial.println("\n\nESP32 WiFi Sniffer - Slave Node");
  Serial.printf("Node ID: %d\n", DEVICE_ID);

  esp_err_t ret = esp_wifi_init(NULL);
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  buffer_mutex = xSemaphoreCreateMutex();
  packet_queue = xQueueCreate(10, sizeof(wifi_packet_t));
  if (buffer_mutex == NULL || packet_queue == NULL) {
    Serial.println("Failed to create mutex or queue");
    return;
  }

  uint8_t slave_addr = I2C_BASE_ADDR + DEVICE_ID;
  if (DEVICE_ID < 1 || DEVICE_ID > 127) {
    Serial.println("Invalid device ID, must be between 1 and 127");
    return;
  }
  i2c_slave_init(slave_addr);
  
#endif

}

void loop() {
#ifdef MONITOR
  task_runner();
#endif
}
