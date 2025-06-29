#!/usr/bin/env python3
"""Main entry point for the RPI Master Service."""

import sys
import os
import signal
import time
import logging

# Add src directory to path when running from root
if __name__ == "__main__":
    # Get the directory containing this script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Add parent directory (src) to Python path
    sys.path.insert(0, os.path.dirname(current_dir))

from src.config.settings import config
from src.services.rpi_service import spi_service
from src.utils.helpers import setup_logging, SPIPacketType

logger = logging.getLogger(__name__)

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info("Received shutdown signal")
    spi_service.stop()
    sys.exit(0)

def on_data_packet(pkt_type, seq, payload, metadata):
    """Handle received data packets."""
    logger.info(f"Received data packet seq {seq} from device {metadata['device_id']} on channel {metadata['channel']}: {payload.decode('utf-8', errors='ignore')[:50]}...")
    # Send ACK back
    spi_service.send_ack()

def on_status_packet(pkt_type, seq, payload, metadata):
    """Handle status packets."""
    logger.info(f"Received status packet seq {seq} from device {metadata['device_id']} on channel {metadata['channel']}: {payload.hex()}")

def main():
    """Main application function."""
    setup_logging(config.log_level)
    logger.info("RPI Master Service starting...")
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Register packet callbacks
        spi_service.register_packet_callback(SPIPacketType.SPI_DATA_PKT, on_data_packet)
        spi_service.register_packet_callback(SPIPacketType.SPI_SSTAT, on_status_packet)
        
        # Start SPI service
        spi_service.start()
        
        # Example: Send start data command
        time.sleep(1)
        spi_service.send_start_data()
        
        # Main loop - process received packets
        while True:
            packet = spi_service.get_received_packet(timeout=1.0)
            if packet:
                pkt_type, seq, payload = packet
                logger.debug(f"Main loop processing: type={pkt_type}, seq={seq}")
            
            # Example: Send periodic continue data commands
            time.sleep(5)
            spi_service.send_continue_data()

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Application error: {e}")
    finally:
        spi_service.stop()
        logger.info("Application stopped")

if __name__ == "__main__":
    main()