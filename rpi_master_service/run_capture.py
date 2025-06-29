#!/usr/bin/env python3
"""
WiFi Capture Automation Script
Runs the WiFi sniffer, filters beacons, extracts Layer 3 packets, and runs Suricata analysis
"""

import subprocess
import time
import os
import sys
import argparse
import logging
import signal
import glob
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WiFiCaptureAutomation:
    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir) if base_dir else Path.cwd()
        self.captures_dir = self.base_dir / "captures"
        self.filtered_dir = self.base_dir / "filtered_captures" 
        self.layer3_dir = self.base_dir / "layer3_captures"
        self.logs_dir = self.base_dir / "logs"
        
        # Script paths (adjust these based on your actual file locations)
        self.sniffer_script = self.base_dir / "create_pcap_file.py"
        self.beacon_filter_script = self.base_dir / "wifi_beacon_filter.py"
        self.layer3_extractor_script = self.base_dir / "extract_ip_layer.py"
        self.suricata_config = self.base_dir / "suricata.yaml"
        self.suricata_rules = self.base_dir / "suricata.rules"
        
        self.current_process = None
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    def validate_pcap_file(self, pcap_file):
        """Validate that PCAP file has content and proper structure."""
        if not pcap_file.exists():
            logger.error(f"PCAP file does not exist: {pcap_file}")
            return False
            
        # Check file size (PCAP global header is 24 bytes minimum)
        if pcap_file.stat().st_size < 24:
            logger.error(f"PCAP file too small: {pcap_file.stat().st_size} bytes")
            return False
        
        # Check for valid PCAP magic number
        try:
            with open(pcap_file, 'rb') as f:
                magic = f.read(4)
                if magic not in [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1']:
                    logger.error(f"Invalid PCAP magic number in {pcap_file}")
                    return False
        except Exception as e:
            logger.error(f"Error reading PCAP file {pcap_file}: {e}")
            return False
            
        logger.info(f"PCAP file validated: {pcap_file} ({pcap_file.stat().st_size} bytes)")
        return True
    def setup_directories(self):
        """Create necessary directories."""
        for directory in [self.captures_dir, self.filtered_dir, self.layer3_dir, self.logs_dir]:
            directory.mkdir(exist_ok=True)
            logger.info(f"Ensured directory exists: {directory}")
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        logger.info("Received interrupt signal, stopping capture...")
        if self.current_process:
            self.current_process.terminate()
            try:
                self.current_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("Process didn't terminate gracefully, killing...")
                self.current_process.kill()
        sys.exit(0)
    
    def run_sniffer(self, duration_seconds, debug=False):
        """Run the WiFi sniffer for specified duration."""
        logger.info(f"Starting WiFi capture for {duration_seconds} seconds...")
        
        cmd = [
            "sudo", "python3", str(self.sniffer_script),
            "--duration", str(duration_seconds),
            "--captures-dir", str(self.captures_dir)
        ]
        
        if debug:
            cmd.append("--debug")
        
        try:
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Stream output in real-time
            while True:
                output = self.current_process.stdout.readline()
                if output == '' and self.current_process.poll() is not None:
                    break
                if output:
                    print(f"[SNIFFER] {output.strip()}")
            
            rc = self.current_process.wait()
            self.current_process = None
            
            if rc != 0:
                logger.error(f"WiFi sniffer failed with return code {rc}")
                return False
            
            logger.info("WiFi capture completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error running WiFi sniffer: {e}")
            return False
    
    def get_latest_capture_file(self):
        """Find the most recently created capture file."""
        pcap_files = list(self.captures_dir.glob("wifi_capture_*.pcap"))
        if not pcap_files:
            logger.error("No capture files found!")
            return None
        
        # Sort by modification time, get the newest
        latest_file = max(pcap_files, key=lambda f: f.stat().st_mtime)
        logger.info(f"Latest capture file: {latest_file}")
        return latest_file
    
    def filter_beacons(self, input_file, debug=False):
        """Filter beacon frames from the capture."""
        logger.info("Filtering beacon frames...")
        
        output_file = self.filtered_dir / f"filtered_{input_file.name}"
        
        cmd = [
            "python3", str(self.beacon_filter_script),
            str(input_file),
            str(output_file)
        ]
        
        if debug:
            cmd.append("--debug")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Beacon filtering failed: {result.stderr}")
                return None
            
            # Print filter output
            for line in result.stdout.split('\n'):
                if line.strip():
                    print(f"[FILTER] {line}")
            
            logger.info(f"Beacon filtering completed: {output_file}")
            return output_file
            
        except subprocess.TimeoutExpired:
            logger.error("Beacon filtering timed out")
            return None
        except Exception as e:
            logger.error(f"Error filtering beacons: {e}")
            return None
    
    def extract_layer3(self, input_file, debug=False):
        """Extract Layer 3 packets."""
        logger.info("Extracting Layer 3 packets...")
        
        output_file = self.layer3_dir / f"layer3_{input_file.name.replace('filtered_', '')}"
        
        cmd = [
            "python3", str(self.layer3_extractor_script),
            str(input_file),
            str(output_file)
        ]
        
        if debug:
            cmd.append("--debug")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Layer 3 extraction failed: {result.stderr}")
                return None
            
            # Print extraction output
            for line in result.stdout.split('\n'):
                if line.strip():
                    print(f"[LAYER3] {line}")
            
            # Check if output file exists and has content
            if not self.validate_pcap_file(output_file):
                logger.warning("Layer 3 extraction produced no usable output")
                return None
            
            logger.info(f"Layer 3 extraction completed: {output_file}")
            return output_file
            
        except subprocess.TimeoutExpired:
            logger.error("Layer 3 extraction timed out")
            return None
        except Exception as e:
            logger.error(f"Error extracting Layer 3: {e}")
            return None
    
    def run_suricata_analysis(self, input_file):
        """Run Suricata analysis on the Layer 3 PCAP."""
        if not self.validate_pcap_file(input_file):
            logger.error("Cannot run Suricata on invalid PCAP file")
            return False
        
        if not self.suricata_config.exists():
            logger.warning(f"Suricata config not found: {self.suricata_config}")
            return False
        
        if not self.suricata_rules.exists():
            logger.warning(f"Suricata rules not found: {self.suricata_rules}")
            return False
        
        logger.info("Running Suricata analysis...")
        
        # Create session-specific log directory
        session_log_dir = self.logs_dir / f"session_{self.session_id}"
        session_log_dir.mkdir(exist_ok=True)
        
        cmd = [
            "suricata",
            "-c", str(self.suricata_config),
            "-r", str(input_file),
            # "-s", str(self.suricata_rules),
            "-l", str(session_log_dir)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            # Print Suricata output
            if result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        print(f"[SURICATA] {line}")
            
            if result.stderr:
                for line in result.stderr.split('\n'):
                    if line.strip():
                        print(f"[SURICATA-ERR] {line}")
            
            if result.returncode != 0:
                logger.warning(f"Suricata completed with warnings (return code {result.returncode})")
            else:
                logger.info("Suricata analysis completed successfully")
            
            # Show results summary
            self.show_suricata_results(session_log_dir)
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("Suricata analysis timed out")
            return False
        except FileNotFoundError:
            logger.error("Suricata not found. Please install Suricata or adjust PATH")
            return False
        except Exception as e:
            logger.error(f"Error running Suricata: {e}")
            return False
    
    def show_suricata_results(self, log_dir):
        """Show summary of Suricata analysis results."""
        fast_log = log_dir / "fast.log"
        eve_log = log_dir / "eve.json"
        
        print("\n" + "="*60)
        print("SURICATA ANALYSIS RESULTS")
        print("="*60)
        
        if fast_log.exists():
            try:
                with open(fast_log, 'r') as f:
                    alerts = f.readlines()
                if alerts:
                    print(f"ALERTS FOUND: {len(alerts)}")
                    print("\nFirst few alerts:")
                    for i, alert in enumerate(alerts[:5]):
                        print(f"  {i+1}: {alert.strip()}")
                    if len(alerts) > 5:
                        print(f"  ... and {len(alerts) - 5} more alerts")
                else:
                    print("No alerts generated")
            except Exception as e:
                logger.error(f"Error reading fast.log: {e}")
        else:
            print("No fast.log generated")
        
        print(f"\nLogs saved to: {log_dir}")
        print(f"  - Fast log: {fast_log}")
        print(f"  - EVE JSON: {eve_log}")
        print("="*60)
    
    def run_full_pipeline(self, duration_seconds, debug=False, skip_suricata=False):
        """Run the complete capture and analysis pipeline."""
        logger.info(f"Starting WiFi capture automation (Session: {self.session_id})")
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Step 1: Setup directories
            self.setup_directories()
            
            # Step 2: Run WiFi sniffer
            if not self.run_sniffer(duration_seconds, debug):
                logger.error("WiFi capture failed, aborting pipeline")
                return False
            
            # Step 3: Find latest capture file
            capture_file = self.get_latest_capture_file()
            if not capture_file:
                logger.error("No capture file found, aborting pipeline")
                return False
            
            # Step 4: Filter beacon frames
            filtered_file = self.filter_beacons(capture_file, debug)
            if not filtered_file:
                logger.error("Beacon filtering failed, aborting pipeline")
                return False
            
            # Step 5: Extract Layer 3 packets
            layer3_file = self.extract_layer3(filtered_file, debug)
            if not layer3_file:
                logger.warning("Layer 3 extraction failed or produced no data")
                logger.info("This is normal if no data frames were captured")
                return True  # Not a failure, just no data frames
            
            # Step 6: Run Suricata analysis (optional)
            if not skip_suricata:
                self.run_suricata_analysis(layer3_file)
            else:
                logger.info("Skipping Suricata analysis (--skip-suricata specified)")
            
            logger.info("WiFi capture automation completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

def main():
    parser = argparse.ArgumentParser(description='Automated WiFi Capture and Analysis Pipeline')
    parser.add_argument('duration', type=int, help='Capture duration in seconds')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--skip-suricata', action='store_true', help='Skip Suricata analysis')
    parser.add_argument('--base-dir', help='Base directory for all operations (default: current directory)')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.duration <= 0:
        logger.error("Duration must be positive")
        return 1
    
    # Create automation instance
    automation = WiFiCaptureAutomation(args.base_dir)
    
    # Run the pipeline
    success = automation.run_full_pipeline(
        duration_seconds=args.duration,
        debug=args.debug,
        skip_suricata=args.skip_suricata
    )
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())