#include "../include/include.h"
#include "../include/spi_protocol_incl.h"
#include "soc/soc.h"
// #include "soc/rtc_cntl_reg.h"

// Global variable definitions
QueueHandle_t packet_queue = NULL;
SemaphoreHandle_t buffer_mutex = NULL;

// Simplified - no state machine, just continuously listen
static bool sniffer_active = false;

#ifdef MONITOR

static void print_packet_info(wifi_packet_t *pkt)
{
  //   Serial.printf("[CH%d] Packet: %u.%06u, len=%d bytes\n",
  // WIFI_CHANNEL, pkt->ts_sec, pkt->ts_usec, pkt->length);

  // Optional: Print first few bytes of payload in hex
  //   Serial.print("Data: ");
  int print_len = (pkt->length > 16) ? 16 : pkt->length;
  for (int i = 0; i < print_len; i++)
  {
    // Serial.printf("%02X ", pkt->payload[i]);
  }
  //   if (pkt->length > 16) Serial.print("...");
  //   Serial.println();
}

static void packet_forwarding_task(void *pvParameters)
{
  wifi_packet_t *pkt;
  // static unsigned long last_stats = 0;
  static uint32_t packets_this_second = 0;

  // Handle SPI commands from master (these come as structured packets)
  spi_packet_t received_pkt;
  while (true)
  {
    {
      if (xQueueReceive(packet_queue, &pkt, 0) == pdTRUE)
      {
        // vTaskDelay(20 / portTICK_PERIOD_MS); // Simulate processing delay
        if (!pkt)
          continue;
        // ESP_LOGI("PACKET_FORWARDER", "Received packet: %u.%06u, len=%d bytes",
        //  pkt->ts_sec, pkt->ts_usec, pkt->length);
        // print_packet_info(pkt);
        packets_this_second++;
        spi_packet_t spi_pkt = {0};
        spi_pkt.magic = SPI_MAGIC;
        spi_pkt.type = SPI_DATA_PKT;
        spi_pkt.seq = 0;
        spi_pkt.id.channel = wifi_sniffer_get_channel();
        spi_pkt.id.device_id = DEVICE_ID;
        spi_pkt.id.wifi_packet_length = pkt->length;
        spi_pkt.time.ts_sec = pkt->ts_sec;
        spi_pkt.time.ts_usec = pkt->ts_usec;

        uint8_t *payload = spi_pkt.payload;
        // payload[0] = 0x02;
        // payload[1] = DEVICE_ID;
        // payload[2] = WIFI_CHANNEL;
        // payload[3] = (pkt->length >> 8) & 0xFF;
        // payload[4] = pkt->length & 0xFF;

        // memcpy(&payload[5], &pkt->ts_sec, 4);
        // memcpy(&payload[9], &pkt->ts_usec, 4);

        uint16_t wifi_data_space = SPI_MAX_PAYLOAD;
        uint16_t copy_len =
            pkt->length < wifi_data_space ? pkt->length : wifi_data_space;

        if (copy_len > 0)
        {
          memcpy(payload, pkt->payload, copy_len);
          spi_pkt.payload_len = copy_len;
        }
        else
        {
          spi_pkt.payload_len = 0;
        }

        if (!spi_add_packet(&spi_pkt))
          ESP_LOGI("PACKET_FORWARDER", "ERROR: SPI queue full or uninitialized");
        else
          ESP_LOGI("PACKET_FORWARDER", "Added to SPI queue");
        free(pkt);
      }
    }

    if (!spi_read_packet(&received_pkt))
    {
      vTaskDelay(10 / portTICK_PERIOD_MS); // No packet available, wait a bit
      continue;                            // Retry reading packet
    }
  
    uint8_t cmd_type = received_pkt.payload[0];

    switch (cmd_type)
    {
    case 0x03: // Channel change command
    {
      uint8_t new_channel = received_pkt.id.channel;
      if (new_channel >= 1 && new_channel <= 13)
      {
        if (sniffer_active)
        {
          esp_wifi_set_promiscuous(false);
          vTaskDelay(100 / portTICK_PERIOD_MS);
          wifi_sniffer_set_channel(new_channel);
          esp_wifi_set_promiscuous(true);
        }
      }
    }
    break;

    case 0x04: // Start/stop sniffer command
    {
      bool should_start = received_pkt.payload[1];
      if (should_start && !sniffer_active)
      {
        wifi_sniffer_init();
        sniffer_active = true;
        ESP_LOGI("PACKET_FORWARDER", "Sniffer started by master");
      }
      else if (!should_start && sniffer_active)
      {
        esp_wifi_set_promiscuous(false);
        sniffer_active = false;
        ESP_LOGI("PACKET_FORWARDER", "Sniffer stopped by master");
      }
    }
    break;

    case 0x05: // Status request
    {
      spi_packet_t status_pkt = {0};
      status_pkt.magic = SPI_MAGIC;
      status_pkt.type = SPI_SSTAT;       // Response type
      status_pkt.seq = received_pkt.seq; // Respond with same sequence

      // Prepare status response payload
      status_pkt.id.channel = wifi_sniffer_get_channel();
      status_pkt.id.device_id = DEVICE_ID;
      status_pkt.id.wifi_packet_length = 0; // Not used in status
      status_pkt.time.ts_sec =  time(NULL); // Current time in seconds
      status_pkt.time.ts_usec = 0; // Microseconds not used in status
      status_pkt.payload[0] = sniffer_active ? 1 : 0; // Sniffer active status
      status_pkt.payload[1] = packets_this_second & 0xFF; // Packets this second (low byte)
      status_pkt.payload[2] = (packets_this_second >> 8) & 0xFF; // Packets this second (high byte)

      spi_add_packet(&status_pkt);
    }
    break;

    default:
      if (cmd_type != 0x02)
        //   Serial.printf("Unknown command from master: 0x%02X\n", cmd_type);
        break;
    }
  }
}

#endif

void app_main()
{
  // Power management
  //   Serial.begin(115200);
  //   delay(1000);
  vTaskDelay(1000 / portTICK_PERIOD_MS); // Allow time for serial to stabilize
  // WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
#ifdef MONITOR

  // Initialize SPI protocol first
  //   Serial.println("Initializing SPI protocol...");
  esp_err_t spi_ret = spi_protocol_init(GPIO_MOSI, GPIO_MISO, GPIO_SCLK, GPIO_CS);
  if (spi_ret != ESP_OK)
  {
    // Serial.printf("SPI init failed: %s\n", esp_err_to_name(spi_ret));
    // while(1) delay(1000);
    while (1)
      vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
  //   Serial.println("SPI protocol ready.");

  // Initialize NVS and WiFi stack
  //   Serial.println("Initializing WiFi stack...");
  esp_err_t ret_nvs = nvs_flash_init();
  if (ret_nvs == ESP_ERR_NVS_NO_FREE_PAGES || ret_nvs == ESP_ERR_NVS_NEW_VERSION_FOUND)
  {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret_nvs = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret_nvs);

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  esp_wifi_start();

  // Create packet queue and mutex
  buffer_mutex = xSemaphoreCreateMutex();
  packet_queue = xQueueCreate(10, sizeof(wifi_packet_t *));
  if (buffer_mutex == NULL || packet_queue == NULL)
  {
    while (1)
      vTaskDelay(1000 / portTICK_PERIOD_MS);
  }

  vTaskDelay(500 / portTICK_PERIOD_MS); // Allow time for WiFi to stabilize

  wifi_sniffer_init();
  sniffer_active = true;

  printf("\n=== ESP32 WiFi Packet Monitor ===\n");
  xTaskCreatePinnedToCore(
      spi_transaction_task,
      "SPI_TRANSACTION_TASK",
      4096 * 8,
      NULL,
      6,
      NULL,
      0);
  printf("\n=== SPI Transaction Task Started ===\n");
  xTaskCreatePinnedToCore(
      packet_forwarding_task,
      "TRANSACTION_PROC_TASK",
      4096 * 8,
      NULL,
      5,
      NULL,
      0);
  printf("\n=== Packet Monitor Task Started ===\n");

#endif
}
