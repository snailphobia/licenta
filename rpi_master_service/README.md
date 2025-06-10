# RPI Master Service

A Python application for Raspberry Pi that communicates with ESP32 devices via SPI protocol.

## Features

- SPI Master communication with ESP32 slaves
- Packet-based protocol with checksums and sequence numbers
- Asynchronous packet handling with queues
- Configurable SPI settings
- Logging and error handling

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Enable SPI on Raspberry Pi:
```bash
sudo raspi-config
# Navigate to Interface Options > SPI > Enable
```

## Usage

Run the application:
```bash
python run_app.py
```

Or install and run:
```bash
pip install -e .
rpi-master
```

## Configuration

Edit `src/config/settings.py` to modify SPI settings:
- Bus and device numbers
- Speed and mode
- Protocol constants

## Wiring

Connect ESP32 to Raspberry Pi:
- ESP32 GPIO23 (MOSI) → RPi GPIO10 (MOSI)
- ESP32 GPIO19 (MISO) → RPi GPIO9 (MISO)  
- ESP32 GPIO18 (SCLK) → RPi GPIO11 (SCLK)
- ESP32 GPIO5 (CS) → RPi GPIO8 (CE0)
- Common ground connection