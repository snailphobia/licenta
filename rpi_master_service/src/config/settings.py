"""Configuration settings for the RPI Master Service."""

import os
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class SPIConfig:
    """SPI configuration settings."""
    bus: int = 0  # SPI bus number (0 or 1)
    device: int = 0  # SPI device number (CE pin)
    max_speed_hz: int = 250000 # 250 KHz
    mode: int = 0  # SPI mode (0-3)
    bits_per_word: int = 8
    
    # Protocol constants matching ESP32
    magic: int = 0x69
    max_payload: int = 1500
    header_size: int = 8
    max_packet: int = header_size + max_payload

@dataclass
class AppConfig:
    """Application configuration."""
    debug: bool = field(default_factory=lambda: os.getenv('DEBUG', 'False').lower() == 'true')
    log_level: str = field(default_factory=lambda: os.getenv('LOG_LEVEL', 'INFO'))
    spi: SPIConfig = field(default_factory=SPIConfig)

# Global config instance
config = AppConfig()
