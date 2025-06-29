#!/usr/bin/env python3
"""
WiFi Sniffer via SPI - Creates PCAP files from WiFi packets received via SPI from ESP32.
Fixed to create proper Radiotap headers.
"""

import spidev
import struct
import time
import logging
import os
import sys
import csv
import threading
from datetime import datetime

# Add src directory to path
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

from src.config.settings import config
from src.utils.helpers import parse_spi_packet, SPIPacketType

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WiFiSniffer:
    def __init__(self):
        self.spi = None
        self.pcap_file = None
        self.packet_count = 0
        self.invalid_packets = 0
        self.captures_dir = "captures"
        
        # Statistics tracking for packets per second
        self.stats_lock = threading.Lock()
        self.stats_start_time = None
        self.stats_packets_count = 0
        self.stats_logging_interval = 10  # seconds
        self.stats_csv_file = None
        self.stats_csv_writer = None
        self.stats_thread = None
        self.stats_running = False
        
        # Time-based packet counters
        self.last_stats_time = None
        self.last_stats_packets = 0
        
    def ensure_captures_directory(self):
        """Create captures directory if it doesn't exist."""
        if not os.path.exists(self.captures_dir):
            os.makedirs(self.captures_dir)
            logger.info(f"Created captures directory: {self.captures_dir}")
        
    def initialize_spi(self):
        """Initialize SPI connection."""
        try:
            self.spi = spidev.SpiDev()
            self.spi.open(config.spi.bus, config.spi.device)
            self.spi.max_speed_hz = config.spi.max_speed_hz
            self.spi.mode = config.spi.mode
            self.spi.bits_per_word = config.spi.bits_per_word
            
            logger.info(f"SPI initialized: bus={config.spi.bus}, device={config.spi.device}, "
                       f"speed={config.spi.max_speed_hz}Hz")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize SPI: {e}")
            return False
    
    def write_pcap_global_header(self, pcap_file):
        """Write PCAP global header for 802.11 with Radiotap."""
        pcap_file.write(struct.pack(
            '!IHHIIII',
            0xa1b2c3d4,  # magic_number
            2,           # version_major
            4,           # version_minor
            0,           # thiszone (GMT to local correction)
            0,           # sigfigs (accuracy of timestamps)
            65535,       # snaplen (max length of captured packets)
            127          # network (LINKTYPE_IEEE802_11_RADIOTAP)
        ))
    
    def create_radiotap_header(self, channel=0, rssi=-50, rate=0):
        """
        Create a minimal Radiotap header for the 802.11 frame.
        This header tells tools like Wireshark how to parse the 802.11 frame.
        """
        # Radiotap header fields we want to include
        # Bit 0: TSFT (timestamp)
        # Bit 1: Flags
        # Bit 2: Rate
        # Bit 3: Channel
        # Bit 5: Antenna signal (RSSI)
        
        present_flags = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5)  # Flags, Rate, Channel, Antenna signal
        
        # Calculate header length
        # 8 bytes: version(1) + pad(1) + length(2) + present(4)
        # 1 byte: flags
        # 1 byte: rate
        # 4 bytes: channel (freq + flags)
        # 1 byte: antenna signal (RSSI)
        # 1 byte: padding for alignment
        header_len = 16
        
        # Build the header
        header = struct.pack('<BBHI',
                           0,           # version
                           0,           # pad
                           header_len,  # length
                           present_flags)  # present flags
        
        # Add fields
        header += struct.pack('<B', 0)        # flags (no special flags)
        header += struct.pack('<B', rate)     # rate (0 = unknown)
        
        # Channel: frequency (MHz) + channel flags
        if channel > 0:
            # Convert channel to frequency (rough approximation)
            if channel <= 14:
                freq = 2407 + (channel * 5)  # 2.4 GHz
            else:
                freq = 5000 + (channel * 5)  # 5 GHz
        else:
            freq = 2412  # Default to channel 1
            
        channel_flags = 0x00A0  # 2GHz + Dynamic CCK-OFDM
        header += struct.pack('<HH', freq, channel_flags)
        
        # Antenna signal (RSSI)
        header += struct.pack('<b', rssi)     # signed byte for RSSI
        header += struct.pack('<B', 0)       # padding
        
        return header
    
    def write_pcap_packet(self, pcap_file, wifi_frame_data, timestamp_sec, timestamp_usec, channel=0, rssi=-50):
        """Write a PCAP packet record with proper Radiotap header."""
        
        # Create Radiotap header
        radiotap_header = self.create_radiotap_header(channel, rssi)
        
        # Combine Radiotap header + 802.11 frame
        complete_packet = radiotap_header + wifi_frame_data
        
        # Write packet header
        pcap_file.write(struct.pack(
            '!IIII',
            timestamp_sec,           # ts_sec (timestamp seconds)
            timestamp_usec,          # ts_usec (timestamp microseconds)
            len(complete_packet),    # incl_len (number of octets saved in file)
            len(complete_packet)     # orig_len (actual length of packet)
        ))
        
        # Write packet data
        pcap_file.write(complete_packet)
    
    def create_pcap_filename(self):
        """Create a timestamped PCAP filename in the captures directory."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"wifi_capture_{timestamp}.pcap"
        return os.path.join(self.captures_dir, filename)
    
    def read_spi_packet(self):
        """Read a packet from SPI."""
        try:
            # Send dummy bytes to read data from ESP32
            buffer = [0x42] * config.spi.max_packet
            response = self.spi.xfer2(buffer)
            response_bytes = bytes(response)
            
            # Check if we got valid data (not all zeros)
            if sum(response[:config.spi.header_size]) == 0:
                return None
                
            return response_bytes
        except Exception as e:
            logger.error(f"SPI read error: {e}")
            return None
    
    def create_stats_csv_filename(self):
        """Create a timestamped CSV filename for statistics in the captures directory."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"wifi_stats_{timestamp}.csv"
        return os.path.join(self.captures_dir, filename)
    
    def start_stats_logging(self):
        """Start background statistics logging."""
        if self.stats_running:
            return
        
        # Create CSV file for statistics
        stats_filename = self.create_stats_csv_filename()
        try:
            self.stats_csv_file = open(stats_filename, 'w', newline='')
            self.stats_csv_writer = csv.writer(self.stats_csv_file)
            
            # Write CSV header
            self.stats_csv_writer.writerow(['timestamp', 'elapsed_seconds', 'total_packets', 'packets_per_second'])
            self.stats_csv_file.flush()
            
            logger.info(f"Started statistics logging to: {stats_filename}")
        except Exception as e:
            logger.error(f"Failed to create statistics CSV file: {e}")
            return False
        
        # Initialize timing
        with self.stats_lock:
            self.stats_start_time = time.time()
            self.last_stats_time = self.stats_start_time
            self.last_stats_packets = 0
            self.stats_running = True
        
        # Start background thread
        self.stats_thread = threading.Thread(target=self._stats_logger_thread, daemon=True)
        self.stats_thread.start()
        
        return True
    
    def stop_stats_logging(self):
        """Stop background statistics logging."""
        with self.stats_lock:
            self.stats_running = False
        
        if self.stats_thread and self.stats_thread.is_alive():
            self.stats_thread.join(timeout=2.0)
        
        if self.stats_csv_file:
            try:
                self.stats_csv_file.close()
                logger.info("Statistics logging stopped and CSV file closed")
            except Exception as e:
                logger.error(f"Error closing statistics CSV file: {e}")
    
    def _stats_logger_thread(self):
        """Background thread that logs packet statistics every 10 seconds."""
        while True:
            with self.stats_lock:
                if not self.stats_running:
                    break
            
            time.sleep(self.stats_logging_interval)
            
            with self.stats_lock:
                if not self.stats_running:
                    break
                
                current_time = time.time()
                current_packets = self.packet_count
                
                # Calculate time elapsed since start
                elapsed_seconds = current_time - self.stats_start_time
                
                # Calculate packets per second for this interval
                time_interval = current_time - self.last_stats_time
                packets_interval = current_packets - self.last_stats_packets
                
                if time_interval > 0:
                    packets_per_second = packets_interval / time_interval
                else:
                    packets_per_second = 0
                
                # Create timestamp string
                timestamp_str = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
                
                # Log to console
                logger.info(f"Stats: {current_packets} total packets, "
                           f"{packets_per_second:.2f} packets/sec over last {time_interval:.1f}s")
                
                # Write to CSV
                if self.stats_csv_writer:
                    try:
                        self.stats_csv_writer.writerow([
                            timestamp_str,
                            f"{elapsed_seconds:.1f}",
                            current_packets,
                            f"{packets_per_second:.2f}"
                        ])
                        self.stats_csv_file.flush()
                    except Exception as e:
                        logger.error(f"Error writing to statistics CSV: {e}")
                
                # Update for next interval
                self.last_stats_time = current_time
                self.last_stats_packets = current_packets
    
    def increment_packet_count(self):
        """Thread-safe method to increment packet count."""
        with self.stats_lock:
            self.packet_count += 1
    
    def start_sniffing(self, duration_seconds=None):
        """Start WiFi packet sniffing via SPI."""
        if not self.initialize_spi():
            return False
        
        # Ensure captures directory exists
        self.ensure_captures_directory()
        
        pcap_filename = self.create_pcap_filename()
        
        # Start statistics logging
        if not self.start_stats_logging():
            logger.warning("Failed to start statistics logging, continuing without stats")
        
        try:
            with open(pcap_filename, 'wb') as self.pcap_file:
                self.write_pcap_global_header(self.pcap_file)
                logger.info(f"Started WiFi sniffing. Saving to {pcap_filename}")
                logger.info("Press Ctrl+C to stop sniffing")
                
                start_time = time.time()
                
                # Start statistics logging in background
                self.start_stats_logging()
                
                while True:
                    # Check duration limit
                    if duration_seconds and (time.time() - start_time) > duration_seconds:
                        logger.info(f"Reached duration limit of {duration_seconds} seconds")
                        break
                    
                    # Read SPI packet
                    spi_data = self.read_spi_packet()
                    if not spi_data:
                        time.sleep(0.001)  # Small delay to prevent busy waiting
                        continue
                    
                    # Debug: Show raw SPI data
                    logger.debug(f"Raw SPI data (first 32 bytes): {spi_data[:32].hex()}")
                    
                    # Parse SPI packet - let parse_spi_packet handle magic byte validation
                    parsed = parse_spi_packet(spi_data)
                    if not parsed:
                        logger.debug("Failed to parse SPI packet - likely invalid magic bytes or format")
                        self.invalid_packets += 1
                        continue
                    
                    pkt_type_val, seq, payload_len, payload, metadata = parsed
                    
                    # Only process WiFi data packets
                    try:
                        pkt_type = SPIPacketType(pkt_type_val)
                        if pkt_type != SPIPacketType.SPI_DATA_PKT:
                            logger.debug(f"Skipping non-data packet type: {pkt_type}")
                            continue
                    except ValueError:
                        logger.debug(f"Unknown packet type: {pkt_type_val}")
                        continue
                    
                    # Skip empty payloads
                    if payload_len == 0:
                        logger.debug("Skipping empty payload")
                        continue
                    
                    # Extract WiFi frame (payload contains the actual 802.11 frame)
                    wifi_frame = payload[:payload_len]
                    
                    # Use timestamp and metadata from SPI packet
                    ts_sec = metadata.get('ts_sec', int(time.time()))
                    ts_usec = metadata.get('ts_usec', int((time.time() % 1) * 1000000))
                    channel = metadata.get('channel', 1)
                    rssi = metadata.get('rssi', -50)
                    device_id = metadata.get('device_id', 0)
                    
                    # Write to PCAP file with proper Radiotap header
                    self.write_pcap_packet(self.pcap_file, wifi_frame, ts_sec, ts_usec, channel, rssi)
                    self.increment_packet_count()
                    
                    # Log packet info
                    logger.info(f"WiFi packet #{self.packet_count}: {payload_len} bytes, "
                               f"channel={channel}, device={device_id}, rssi={rssi}dBm, "
                               f"seq={seq}, ts={ts_sec}.{ts_usec:06d}")
                    
                    # Optional: Print first few bytes of WiFi frame for debugging
                    if payload_len > 0:
                        logger.debug(f"WiFi frame hex: {wifi_frame[:16].hex()}")
                    
                    # Flush file periodically
                    if self.packet_count % 10 == 0:
                        self.pcap_file.flush()
                        
        except KeyboardInterrupt:
            logger.info("Sniffing stopped by user")
        except Exception as e:
            logger.error(f"Error during sniffing: {e}")
        finally:
            self.cleanup()
            logger.info(f"Captured {self.packet_count} valid WiFi packets to {pcap_filename}")
            if self.invalid_packets > 0:
                logger.info(f"Discarded {self.invalid_packets} packets with invalid format")
        
        return True
    
    def cleanup(self):
        """Clean up resources."""
        # Stop statistics logging first
        self.stop_stats_logging()
        
        if self.spi:
            try:
                self.spi.close()
                logger.info("SPI connection closed")
            except Exception as e:
                logger.error(f"Error closing SPI: {e}")

def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='WiFi Sniffer via SPI')
    parser.add_argument('--duration', type=int, help='Capture duration in seconds (default: unlimited)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--captures-dir', default='captures', help='Directory to save capture files (default: captures)')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    sniffer = WiFiSniffer()
    
    # Override captures directory if specified
    if args.captures_dir:
        sniffer.captures_dir = args.captures_dir
    
    try:
        sniffer.start_sniffing(duration_seconds=args.duration)
    except Exception as e:
        logger.error(f"Application error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())