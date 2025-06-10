"""Helper utilities for the RPI Master Service."""

import struct
import logging
from typing import Optional, Tuple
from enum import IntEnum

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
                     magic: int = 0x69) -> bytes:
    """
    Create an SPI packet matching ESP32 protocol.
    
    Args:
        data: Payload data
        seq: Sequence number
        packet_type: Type of packet
        magic: Magic byte for validation
        
    Returns:
        Complete packet as bytes
    """
    if len(data) > 1024:
        raise ValueError("Payload too large")
    
    payload_len = len(data)
    checksum = calculate_checksum(data)
    
    # Pack header: magic, type, seq, payload_len, checksum (little-endian)
    header = struct.pack('<BBBBI', magic, packet_type, seq, payload_len, checksum)
    
    # Pad payload to max size if needed
    padded_data = data + b'\x00' * (1024 - len(data))
    
    return header + padded_data

def parse_spi_packet(packet_data: bytes) -> Optional[Tuple[int, int, int, bytes]]:
    """
    Parse received SPI packet.
    
    Args:
        packet_data: Raw packet data
        
    Returns:
        Tuple of (type, seq, payload_len, payload) or None if invalid
    """
    if len(packet_data) < 8:
        return None
    
    # Unpack header
    magic, pkt_type, seq, payload_len, checksum = struct.unpack('<BBBBI', packet_data[:8])
    
    if magic != 0x69:
        logging.warning(f"Invalid magic byte: {magic:02x}")
        # return None
    
    if payload_len > 1024:
        logging.warning(f"Invalid payload length: {payload_len}")
        return None
    
    payload = packet_data[8:8+payload_len]
    
    # Verify checksum
    calculated_checksum = calculate_checksum(payload)
    if calculated_checksum != checksum:
        logging.warning(f"Checksum mismatch: {calculated_checksum} != {checksum}")
        return None
    

    # print the first 16 bytes of the payload for debugging
    # logging.debug(f"Parsed packet: type={pkt_type}, seq={seq}, payload_len={payload_len}, payload={payload[:16].hex()}")
    print(f"Parsed packet: type={pkt_type}, seq={seq}, payload_len={payload_len}, payload={payload[:16].hex()}")
    return pkt_type, seq, payload_len, payload

def setup_logging(level: str = 'INFO'):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )