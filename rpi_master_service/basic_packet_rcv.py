import spidev
import os, sys

from src.config.settings import config

spi = spidev.SpiDev()
spi.open(config.spi.bus, config.spi.device)
spi.max_speed_hz = 2000000

def read_packet():
    buffer = [0x42] * config.spi.max_packet
    bytes_read = spi.xfer2(buffer)
    # print first 32 bytes for debugging
    print("Read bytes:", bytes_read[:32])

while True:
    input()
    read_packet()
    
