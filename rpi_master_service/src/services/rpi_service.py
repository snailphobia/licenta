"""RPI SPI Master Service for communicating with ESP32."""

import time
import logging
import threading
from typing import Optional, Callable, List
from queue import Queue, Empty
import spidev

from ..config.settings import config
from ..utils.helpers import (
    SPIPacketType, 
    create_spi_packet, 
    parse_spi_packet
)

logger = logging.getLogger(__name__)

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
        """Initialize SPI connection."""
        try:
            self.spi = spidev.SpiDev()
            self.spi.open(config.spi.bus, config.spi.device)
            
            # Configure SPI settings
            self.spi.max_speed_hz = config.spi.max_speed_hz
            self.spi.mode = config.spi.mode
            self.spi.bits_per_word = config.spi.bits_per_word
            
            logger.info(f"SPI initialized: bus={config.spi.bus}, device={config.spi.device}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize SPI: {e}")
            return False
    
    def start(self):
        """Start the SPI service threads."""
        if self.running:
            logger.warning("Service already running")
            return

        if not self.spi:
            if not self.initialize():
                raise RuntimeError("Failed to initialize SPI")
        
        self.running = True
        
        # Start communication threads
        self.read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self.write_thread = threading.Thread(target=self._write_loop, daemon=True)
        
        self.read_thread.start()
        self.write_thread.start()
        
        logger.info("SPI service started")
    
    def stop(self):
        """Stop the SPI service."""
        self.running = False
        
        if self.read_thread and self.read_thread.is_alive():
            self.read_thread.join(timeout=1.0)
        
        if self.write_thread and self.write_thread.is_alive():
            self.write_thread.join(timeout=1.0)
        
        if self.spi:
            self.spi.close()
            self.spi = None
        
        logger.info("SPI service stopped")
    
    def send_packet(self, data: bytes, packet_type: SPIPacketType = SPIPacketType.SPI_DATA_PKT):
        """Queue a packet for transmission."""
        packet = create_spi_packet(data, self._next_seq(), packet_type)
        self.tx_queue.put(packet)
        logger.debug(f"Queued packet type {packet_type}, seq {self.seq_counter-1}")
    
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
        """Register callback for specific packet type."""
        self.packet_callbacks[packet_type] = callback
    
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
        """Background thread for reading SPI data."""
        logger.info("Read loop started")
        
        while self.running:
            try:
                # Read full packet size
                response = self.spi.readbytes(config.spi.max_packet)
                
                # Parse packet
                parsed = parse_spi_packet(bytes(response))
                if parsed:
                    pkt_type, seq, payload_len, payload = parsed
                    logger.debug(f"Received packet type {pkt_type}, seq {seq}, len {payload_len}")
                    
                    # Add to receimax_packetve queue
                    self.rx_queue.put((pkt_type, seq, payload))
                    
                    # Call registered callback if available
                    callback = self.packet_callbacks.get(SPIPacketType(pkt_type))
                    if callback:
                        try:
                            callback(pkt_type, seq, payload)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                
                time.sleep(0.1)  # Small delay to prevent overwhelming
                
            except Exception as e:
                if self.running:
                    logger.error(f"Read loop error: {e}")
                time.sleep(0.1)
    
    def _write_loop(self):
        """Background thread for writing SPI data."""
        logger.info("Write loop started")
        
        while self.running:
            try:
                # Get packet from queue with timeout
                try:
                    packet = self.tx_queue.get(timeout=0.1)
                except Empty:
                    continue
                
                # Send packet
                self.spi.writebytes(list(packet))
                logger.debug(f"Sent packet, {len(packet)} bytes")
                
                # Mark task as done
                self.tx_queue.task_done()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Write loop error: {e}")
                time.sleep(0.1)

# Global service instance
spi_service = RPISPIService()