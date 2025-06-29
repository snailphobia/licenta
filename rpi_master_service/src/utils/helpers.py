"""Helper utilities for the RPI Master Service."""

import struct
import logging
from typing import Optional, Tuple
from enum import IntEnum
from src.config.settings import config

class SPIPacketType(IntEnum):
    """SPI packet types matching ESP32 protocol."""
    MASTER_CONTINUE_DATA = 0x00
    MASTER_START_DATA = 0x01
    MASTER_END_DATA = 0x02
    SPI_START_PKT = 0x10
    SPI_END_PKT = 0x11
    SPI_DATA_PKT = 0x12
    MASTER_ACK = 0x20
    SPI_SSTAT = 0x30

def calculate_checksum(data: bytes) -> int:
    """Calculate simple checksum for packet data."""
    return sum(data) & 0xFFFFFFFF

def create_spi_packet(data: bytes, seq: int, packet_type: SPIPacketType, 
                     magic: int = 0x69, channel: int = 0, device_id: int = 0,
                     ts_sec: int = None, ts_usec: int = None) -> bytes:
    """
    Create an SPI packet matching ESP32 protocol with 16-byte header structure.
    
    Args:
        data: Payload data
        seq: Sequence number
        packet_type: Type of packet
        magic: Magic byte for validation
        channel: WiFi channel number
        device_id: Device ID in SPI line
        ts_sec: Timestamp seconds (defaults to current time if None)
        ts_usec: Timestamp microseconds (defaults to current time if None)
        
    Returns:
        Complete packet as bytes
    """
    if len(data) > config.spi.max_payload:
        raise ValueError("Payload too large")
    
    payload_len = len(data)
    
    # Use current time if not specified
    if ts_sec is None or ts_usec is None:
        import time
        current_time = time.time()
        ts_sec = int(current_time)
        ts_usec = int((current_time - ts_sec) * 1000000)
    
    # Pack header (16 bytes):
    # - magic, type, seq, payload_len (4 bytes)
    # - channel, device_id, wifi_packet_length as uint16 (4 bytes)
    # - ts_sec as uint32, ts_usec as uint32 (8 bytes)
    header = struct.pack('<BBBB BBH II', 
                         magic, packet_type, seq, payload_len,
                         channel, device_id, payload_len,  # wifi_packet_length = payload_len
                         ts_sec, ts_usec)
    
    # Pad payload to max size if needed
    padded_data = data + b'\x00' * (config.spi.max_payload - len(data))
    
    return header + padded_data

def parse_spi_packet(packet_data: bytes) -> Optional[Tuple[int, int, int, bytes, dict]]:
    """
    Parse received SPI packet with 16-byte header.
    
    Args:
        packet_data: Raw packet data
        
    Returns:
        Tuple of (type, seq, payload_len, payload, metadata) or None if invalid
        metadata is a dict containing channel, device_id, wifi_packet_length, ts_sec, ts_usec
    """
    if len(packet_data) < 16:  # New header size is 16 bytes
        logging.warning(f"Packet too short: {len(packet_data)} bytes")
        return None
    
    # Unpack 16-byte header
    magic, pkt_type, seq, payload_len, channel, device_id, wifi_packet_length, ts_sec, ts_usec = struct.unpack(
        '<BBBB BBH II', packet_data[:16])
    logging.info(f"Bytes in header are: {[magic, pkt_type, seq, payload_len, channel, device_id, wifi_packet_length, ts_sec, ts_usec]}")
    
    if magic != 0x69:
        logging.warning(f"Invalid magic byte: {magic:02x}")
        return None
    
    if payload_len > config.spi.max_payload:
        logging.warning(f"Invalid payload length: {payload_len}")
        return None
    
    payload = packet_data[16:16+payload_len]
    
    # Create metadata dictionary
    metadata = {
        'channel': channel,
        'device_id': device_id,
        'wifi_packet_length': wifi_packet_length,
        'ts_sec': ts_sec,
        'ts_usec': ts_usec
    }
    
    # Print debug info
    print(f"Parsed packet: type={pkt_type}, seq={seq}, payload_len={payload_len}, "
          f"channel={channel}, device_id={device_id}, ts={ts_sec}.{ts_usec}, "
          f"payload={payload[:16].hex()}")
    
    return pkt_type, seq, payload_len, payload, metadata

def setup_logging(level: str = 'INFO'):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )