"""RPI SPI Master Service for communicating with ESP32."""

import time
import logging
import threading
from typing import Optional, Callable, List
from queue import Queue, Empty
import spidev
import RPi.GPIO as GPIO # Direct import

from ..config.settings import config
from ..utils.helpers import (
    SPIPacketType,
    create_spi_packet,
    parse_spi_packet
)

logger = logging.getLogger(__name__)

# # Define the GPIO pin for data ready signal from ESP32
# # ESP32 GPIO10 is connected to RPi GPIO2
# DATA_READY_PIN = 2 # BCM numbering for GPIO2

class RPISPIService:
    """SPI Master service for Raspberry Pi."""

    def __init__(self):
        self.spi = None
        self.running = False
        self.read_thread = None
        self.write_thread = None

        # Queues for packet handling
        self.tx_queue = Queue()
        self.rx_queue = Queue()

        # Sequence counter
        self.seq_counter = 0

        # Callbacks
        self.packet_callbacks = {}

    def initialize(self) -> bool:
        """Initialize SPI connection and GPIO."""
        try:
            # Initialize SPI
            self.spi = spidev.SpiDev()
            self.spi.open(config.spi.bus, config.spi.device)

            self.spi.max_speed_hz = config.spi.max_speed_hz
            self.spi.mode = config.spi.mode
            self.spi.bits_per_word = config.spi.bits_per_word

            logger.info(f"SPI initialized: bus={config.spi.bus}, device={config.spi.device}, speed={config.spi.max_speed_hz}Hz, mode={config.spi.mode}")

            # Initialize GPIO
            # GPIO.setmode(GPIO.BCM) # Use Broadcom SOC channel numbering
            # GPIO.setup(DATA_READY_PIN, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
            # logger.info(f"GPIO {DATA_READY_PIN} initialized as input with pull-down resistor.")

            return True

        except Exception as e:
            logger.error(f"Failed to initialize SPI or GPIO: {e}")
            # Attempt to clean up GPIO if SPI init failed but GPIO setup was attempted
            # This cleanup is important if setmode or setup partially succeeded
            try:
                GPIO.cleanup() # Cleanup all channels if init fails broadly
            except Exception as gpio_e:
                logger.error(f"Error during GPIO cleanup on initialization failure: {gpio_e}")
            return False

    def start(self):
        """Start the SPI service threads."""
        if self.running:
            logger.warning("Service already running")
            return

        if not self.spi:
            if not self.initialize():
                raise RuntimeError("Failed to initialize SPI/GPIO, cannot start service.")

        self.running = True

        self.read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self.write_thread = threading.Thread(target=self._write_loop, daemon=True)

        self.read_thread.start()
        self.write_thread.start()

        logger.info("SPI service started")

    def stop(self):
        """Stop the SPI service and clean up GPIO."""
        logger.info("Stopping SPI service...")
        self.running = False

        if self.read_thread and self.read_thread.is_alive():
            logger.debug("Joining read thread...")
            self.read_thread.join(timeout=1.5)
            if self.read_thread.is_alive():
                logger.warning("Read thread did not terminate in time.")

        if self.write_thread and self.write_thread.is_alive():
            logger.debug("Joining write thread...")
            self.write_thread.join(timeout=1.0)
            if self.write_thread.is_alive():
                logger.warning("Write thread did not terminate in time.")

        if self.spi:
            try:
                self.spi.close()
                logger.info("SPI connection closed.")
            except Exception as e:
                logger.error(f"Error closing SPI: {e}")
            self.spi = None

        try:
            GPIO.cleanup() # Changed to clean up all channels used by this script
            logger.info("GPIO channels cleaned up.")
        except Exception as e:
            # This can happen if GPIO was never successfully initialized or already cleaned.
            logger.warning(f"Could not clean up GPIO (or already cleaned): {e}")

        logger.info("SPI service stopped.")

    def send_packet(self, data: bytes, packet_type: SPIPacketType = SPIPacketType.SPI_DATA_PKT):
        """Queue a packet for transmission."""
        if not self.running:
            logger.warning("Service not running, cannot send packet.")
            return
        packet = create_spi_packet(data, self._next_seq(), packet_type, magic=config.spi.magic)
        self.tx_queue.put(packet)
        logger.debug(f"Queued packet type {packet_type.name}, seq {self.seq_counter}, len {len(data)}")

    def send_ack(self):
        """Send acknowledgment packet."""
        self.send_packet(b'', SPIPacketType.MASTER_ACK)

    def send_start_data(self):
        """Send start data command."""
        self.send_packet(b'', SPIPacketType.MASTER_START_DATA)

    def send_continue_data(self):
        """Send continue data command."""
        self.send_packet(b'', SPIPacketType.MASTER_CONTINUE_DATA)

    def send_end_data(self):
        """Send end data command."""
        self.send_packet(b'', SPIPacketType.MASTER_END_DATA)

    def register_packet_callback(self, packet_type: SPIPacketType, callback: Callable):
        """Register callback for specific packet type. Callback will receive (type, seq, payload, metadata)"""
        self.packet_callbacks[packet_type] = callback
        logger.info(f"Registered callback for packet type {packet_type.name}")

    def get_received_packet(self, timeout: float = 0.1) -> Optional[tuple]:
        """Get received packet from queue."""
        try:
            return self.rx_queue.get(timeout=timeout)
        except Empty:
            return None

    def _next_seq(self) -> int:
        """Get next sequence number."""
        self.seq_counter = (self.seq_counter + 1) % 256
        return self.seq_counter

    def _read_loop(self):
        """Background thread for reading SPI data, triggered by GPIO."""
        # logger.info(f"Read loop started, waiting for GPIO {DATA_READY_PIN} rising edge.")

        while self.running:
            try:
                if not self.running:
                    logger.debug("Read loop: self.running is false, exiting.")
                    break


                response_list = self.spi.xfer2([0x42] * config.spi.max_packet)
                response_bytes = bytes(response_list)
                
                if sum(response_list[:config.spi.header_size]) == 0 and len(response_list) >= config.spi.header_size:
                    logger.warning(f"SPI transaction returned all zeros in header ({config.spi.header_size} bytes). Slave might not have sent valid data.")

                parsed = parse_spi_packet(response_bytes)
                if parsed:
                    pkt_type_val, seq, payload_len, payload, metadata = parsed
                    try:
                        pkt_type_enum = SPIPacketType(pkt_type_val)
                        logger.debug(f"Received packet type {pkt_type_enum.name} (0x{pkt_type_val:02x}), seq {seq}, len {payload_len}, "
                                    f"channel={metadata['channel']}, device={metadata['device_id']}, time={metadata['ts_sec']}.{metadata['ts_usec']}")
                    except ValueError:
                        logger.warning(f"Received unknown packet type 0x{pkt_type_val:02x}, seq {seq}, len {payload_len}")
                        continue

                    # Include metadata in the queue for subscribers that need it
                    self.rx_queue.put((pkt_type_enum, seq, payload, metadata))

                    callback = self.packet_callbacks.get(pkt_type_enum)
                    if callback:
                        try:
                            callback(pkt_type_enum, seq, payload, metadata)
                        except Exception as e:
                            logger.error(f"Callback error for {pkt_type_enum.name}: {e}")
                else:
                    logger.warning("Failed to parse SPI packet after data ready signal.")

            except RuntimeError as e:
                if self.running:
                    logger.error(f"GPIO related runtime error in read loop: {e}")
                time.sleep(1)
            except Exception as e:
                if self.running:
                    logger.error(f"Read loop error: {e}", exc_info=True)
                time.sleep(0.1)
        logger.info("Read loop terminated.")

    def _write_loop(self):
        """Background thread for writing SPI data."""
        logger.info("Write loop started")

        while self.running:
            try:
                packet_to_send = None
                try:
                    packet_to_send = self.tx_queue.get(timeout=0.1)
                except Empty:
                    continue

                if not self.running:
                    logger.debug("Write loop: self.running is false after tx_queue.get, exiting.")
                    if packet_to_send:
                        self.tx_queue.put(packet_to_send) # Re-queue if stopping
                    break
                
                self.spi.writebytes(packet_to_send)
                
                if len(packet_to_send) > 1:
                    pkt_type_val = packet_to_send[1]
                    try:
                        pkt_type_enum_sent = SPIPacketType(pkt_type_val)
                        logger.debug(f"Sent packet type {pkt_type_enum_sent.name} (0x{pkt_type_val:02x}), {len(packet_to_send)} bytes")
                    except ValueError:
                        logger.debug(f"Sent packet with unknown type 0x{pkt_type_val:02x}, {len(packet_to_send)} bytes")
                else:
                    logger.debug(f"Sent packet, {len(packet_to_send)} bytes (too short to determine type from packet)")

                self.tx_queue.task_done()

            except Exception as e:
                if self.running:
                    logger.error(f"Write loop error: {e}", exc_info=True)
                time.sleep(0.1)
        logger.info("Write loop terminated.")

# Global service instance
spi_service = RPISPIService()
