#include "../include/include.h"
#include "../include/spi_protocol_incl.h"

uint32_t packet_count = 0;

#ifdef MONITOR

void wifi_sniffer_init() {
//   Serial.println("Starting WiFi promiscuous mode...");
  printf("Starting WiFi promiscuous mode...\n");

  // delay(200);
  vTaskDelay(200 / portTICK_PERIOD_MS); // Allow time for WiFi to stabilize
  esp_err_t ret = esp_wifi_set_promiscuous(true);
  if (ret != ESP_OK) {
    // Serial.printf("Failed to set promiscuous mode: %s\n", esp_err_to_name(ret));
    printf("Failed to set promiscuous mode: %s\n", esp_err_to_name(ret));
    return;
  }
  // delay(100);
  vTaskDelay(100 / portTICK_PERIOD_MS); // Allow time for promiscuous mode to take effect
  
  ret = esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  if (ret != ESP_OK) {
    // Serial.printf("Failed to set promiscuous callback: %s\n", esp_err_to_name(ret));
    printf("Failed to set promiscuous callback: %s\n", esp_err_to_name(ret));
    return;
  }
  // delay(100);
  vTaskDelay(100 / portTICK_PERIOD_MS); // Allow time for callback to be set
  
  wifi_sniffer_set_channel(WIFI_CHANNEL);
  
  // Serial.printf("WiFi sniffer active on channel %d\n", WIFI_CHANNEL);
  printf("WiFi sniffer active on channel %d\n", WIFI_CHANNEL);
}

void wifi_sniffer_set_channel(uint8_t channel) {
  if (channel < 1 || channel > 13) {
    // Serial.printf("Invalid channel %d\n", channel);
    printf("Invalid channel %d\n", channel);
    return;
  }

  esp_err_t ret = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  if (ret != ESP_OK) {
    // Serial.printf("Failed to set channel %d: %s\n", channel, esp_err_to_name(ret));
    printf("Failed to set channel %d: %s\n", channel, esp_err_to_name(ret));
    return;
  }
  // delay(50);
  vTaskDelay(50 / portTICK_PERIOD_MS); // Allow time for channel change to take effect
  // Serial.printf("Channel set to %d\n", channel);
  printf("Channel set to %d\n", channel);
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  // Capture all packet types for comprehensive monitoring
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL) {
    return;
  }
// Serial.printf("Found packet of type %d\n", type);
  printf("Found packet of type %d\n", type);
  printf("Excerpt: %02X %02X %02X %02X %02X %02X\n",
         ((uint8_t*)buff)[0], ((uint8_t*)buff)[1], ((uint8_t*)buff)[2],
         ((uint8_t*)buff)[3], ((uint8_t*)buff)[4], ((uint8_t*)buff)[5]);
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_pkt_rx_ctrl_t *rx_ctrl = &ppkt->rx_ctrl;

  // Allocate packet dynamically to avoid stack overflow
  wifi_packet_t *pkt = (wifi_packet_t*)malloc(sizeof(wifi_packet_t));
  if (!pkt) {
    // Out of memory, skip this packet
    return;
  }

  struct timeval tv;
  gettimeofday(&tv, NULL);
  
  pkt->ts_sec = tv.tv_sec;
  pkt->ts_usec = tv.tv_usec;
  pkt->length = rx_ctrl->sig_len;
  
  if (pkt->length > MTU) {
    pkt->length = MTU;
  }
  
  memcpy(pkt->payload, ppkt->payload, pkt->length);
  
  // Send pointer to queue instead of copying entire structure
  BaseType_t result = xQueueSendToBack(packet_queue, &pkt, 0);
  if (result != pdTRUE) {
    // Queue full, free the allocated memory
    free(pkt);
   // Serial.println("Packet not added to queue, queue full");
  } else {
    packet_count++;
    // Serial.println("Packet added to queue number " + String(packet_count));
  }
}

#endif // MONITOR
