#include "../include/include.h"

uint32_t packet_count = 0;

#ifdef MONITOR

void wifi_sniffer_init() {
  Serial.println("Initializing WiFi in promiscuous mode");

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  
  wifi_sniffer_set_channel(WIFI_CHANNEL);
  
  Serial.printf("WiFi sniffer initialized on channel %d\n", WIFI_CHANNEL);
}

void wifi_sniffer_set_channel(uint8_t channel) {
  if (channel < 1 || channel > 13) {
    Serial.println("Invalid channel, must be between 1 and 13");
    return;
  }

  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  Serial.printf("Changed to channel %d\n", channel);
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) {
    return;
  }
  
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_pkt_rx_ctrl_t *rx_ctrl = &ppkt->rx_ctrl;
  
  struct timeval tv;
  gettimeofday(&tv, NULL);
  
  wifi_packet_t pkt;
  pkt.ts_sec = tv.tv_sec;
  pkt.ts_usec = tv.tv_usec;
  pkt.length = rx_ctrl->sig_len;
  
  if (pkt.length > MTU) {
    pkt.length = MTU;
  }
  
  memcpy(pkt.payload, ppkt->payload, pkt.length);
  BaseType_t result = xQueueSendToBack(packet_queue, &pkt, 0);

}

void packet_writer_task(void *pvParameter) {
  wifi_packet_t pkt;
  
  while (1) {
    if (xQueueReceive(packet_queue, &pkt, portMAX_DELAY) == pdTRUE) {
      store_packet_to_buffer(&pkt);
      
      packet_count++;
    }
  }
}

#endif // MONITOR