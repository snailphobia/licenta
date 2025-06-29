#!/usr/bin/env python3
"""
WiFi PCAP Beacon Filter
Removes beacon frames and other management traffic, keeps only data frames and security-relevant frames
"""

import struct
import logging
import os
import sys
import argparse
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WiFiBeaconFilter:
    def __init__(self):
        self.total_packets = 0
        self.kept_packets = 0
        self.filtered_packets = 0
        self.frame_stats = {}
        
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
    
    def write_pcap_packet(self, pcap_file, packet_data, timestamp_sec, timestamp_usec):
        """Write a PCAP packet record."""
        pcap_file.write(struct.pack(
            '!IIII',
            timestamp_sec,    # ts_sec
            timestamp_usec,   # ts_usec
            len(packet_data), # incl_len
            len(packet_data)  # orig_len
        ))
        pcap_file.write(packet_data)
    
    def read_pcap_global_header(self, pcap_file):
        """Read PCAP global header."""
        header = pcap_file.read(24)
        if len(header) != 24:
            return False
            
        magic, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack('!IHHIIII', header)
        
        if magic != 0xa1b2c3d4:
            logger.error("Invalid PCAP magic number")
            return False
            
        logger.info(f"Input PCAP: version={version_major}.{version_minor}, network={network}")
        return True
    
    def read_pcap_packet(self, pcap_file):
        """Read a single packet from PCAP file."""
        packet_header = pcap_file.read(16)
        if len(packet_header) != 16:
            return None
            
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('!IIII', packet_header)
        
        packet_data = pcap_file.read(incl_len)
        if len(packet_data) != incl_len:
            return None
            
        return ts_sec, ts_usec, packet_data
    
    def parse_radiotap_header(self, data):
        """Parse Radiotap header and return its length."""
        if len(data) < 4:
            return 0
            
        try:
            version, pad, radiotap_len = struct.unpack('<BBH', data[0:4])
            return radiotap_len
        except struct.error:
            return 0
    
    def should_keep_frame(self, wifi_frame):
        """
        Determine if a 802.11 frame should be kept for security analysis.
        Returns (keep_frame, frame_description)
        """
        if len(wifi_frame) < 24:
            return False, "Too short"
            
        # Parse Frame Control
        frame_control = struct.unpack('<H', wifi_frame[0:2])[0]
        frame_type = (frame_control >> 2) & 0x3
        frame_subtype = (frame_control >> 4) & 0xF
        
        # Frame type names for logging
        type_names = {0: "Management", 1: "Control", 2: "Data", 3: "Reserved"}
        type_name = type_names.get(frame_type, f"Unknown({frame_type})")
        
        # Management frame subtypes
        mgmt_subtypes = {
            0: "Association Request",
            1: "Association Response", 
            2: "Reassociation Request",
            3: "Reassociation Response",
            4: "Probe Request",
            5: "Probe Response",
            8: "Beacon",
            9: "ATIM",
            10: "Disassociation",
            11: "Authentication",
            12: "Deauthentication"
        }
        
        subtype_name = mgmt_subtypes.get(frame_subtype, f"Subtype {frame_subtype}")
        frame_desc = f"{type_name} - {subtype_name}"
        
        # Track statistics
        self.frame_stats[frame_desc] = self.frame_stats.get(frame_desc, 0) + 1
        
        # KEEP THESE FRAMES (security relevant):
        
        # 1. All Data frames (type 2) - contains actual network traffic
        if frame_type == 2:
            return True, frame_desc
        
        # 2. Security-relevant Management frames
        if frame_type == 0:
            # Keep authentication/deauth frames (attacks)
            if frame_subtype in [11, 12]:  # Authentication, Deauthentication
                return True, frame_desc
            
            # Keep association/disassociation frames (connection attempts)
            if frame_subtype in [0, 1, 2, 3, 10]:  # Assoc Req/Resp, Reassoc Req/Resp, Disassoc
                return True, frame_desc
            
            # Keep probe requests (device discovery)
            if frame_subtype == 4:  # Probe Request
                return True, frame_desc
        
        # 3. All Control frames (type 1) - short but potentially relevant
        if frame_type == 1:
            return True, frame_desc
        
        # FILTER OUT THESE FRAMES (noise):
        
        # 1. Beacon frames (type 0, subtype 8) - too much noise
        if frame_type == 0 and frame_subtype == 8:
            return False, frame_desc
        
        # 2. Probe responses (type 0, subtype 5) - usually noise
        if frame_type == 0 and frame_subtype == 5:
            return False, frame_desc
        
        # 3. ATIM frames (type 0, subtype 9) - rarely relevant
        if frame_type == 0 and frame_subtype == 9:
            return False, frame_desc
        
        # Default: keep unknown frames
        return True, frame_desc
    
    def filter_pcap_file(self, input_file, output_file):
        """Filter beacon frames from PCAP file."""
        logger.info(f"Filtering {input_file} -> {output_file}")
        
        try:
            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Read and validate input header
                if not self.read_pcap_global_header(infile):
                    logger.error(f"Failed to read PCAP header from {input_file}")
                    return False
                
                # Write output header (same format)
                self.write_pcap_global_header(outfile)
                
                # Process packets
                while True:
                    packet_info = self.read_pcap_packet(infile)
                    if packet_info is None:
                        break
                        
                    ts_sec, ts_usec, packet_data = packet_info
                    self.total_packets += 1
                    
                    # Parse Radiotap header
                    radiotap_len = self.parse_radiotap_header(packet_data)
                    if radiotap_len == 0 or radiotap_len >= len(packet_data):
                        self.filtered_packets += 1
                        continue
                    
                    # Get 802.11 frame
                    wifi_frame = packet_data[radiotap_len:]
                    
                    # Check if we should keep this frame
                    keep_frame, frame_desc = self.should_keep_frame(wifi_frame)
                    
                    if keep_frame:
                        # Write the complete packet (Radiotap + 802.11)
                        self.write_pcap_packet(outfile, packet_data, ts_sec, ts_usec)
                        self.kept_packets += 1
                        logger.debug(f"Kept packet {self.total_packets}: {frame_desc}")
                    else:
                        self.filtered_packets += 1
                        logger.debug(f"Filtered packet {self.total_packets}: {frame_desc}")
        
                # Print results
                logger.info(f"Filtering complete:")
                logger.info(f"  Total packets: {self.total_packets}")
                logger.info(f"  Kept packets: {self.kept_packets}")
                logger.info(f"  Filtered packets: {self.filtered_packets}")
                logger.info(f"  Size reduction: {(self.filtered_packets/self.total_packets)*100:.1f}%")
                
                # Print frame statistics
                logger.info(f"Frame type breakdown:")
                for frame_type, count in sorted(self.frame_stats.items(), key=lambda x: x[1], reverse=True):
                    kept_count = count if "Beacon" not in frame_type and "Probe Response" not in frame_type else 0
                    status = "KEPT" if kept_count > 0 else "FILTERED"
                    logger.info(f"  {frame_type}: {count} packets ({status})")
                
                return True
                
        except Exception as e:
            logger.error(f"Error filtering {input_file}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def filter_directory(self, input_dir, output_dir):
        """Filter all PCAP files in a directory."""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
        
        pcap_files = [f for f in os.listdir(input_dir) if f.endswith('.pcap')]
        
        if not pcap_files:
            logger.warning(f"No PCAP files found in {input_dir}")
            return
        
        logger.info(f"Found {len(pcap_files)} PCAP files to filter")
        
        total_original = 0
        total_kept = 0
        
        for pcap_file in pcap_files:
            input_path = os.path.join(input_dir, pcap_file)
            output_filename = f"filtered_{pcap_file}"
            output_path = os.path.join(output_dir, output_filename)
            
            # Create new filter instance for each file
            file_filter = WiFiBeaconFilter()
            success = file_filter.filter_pcap_file(input_path, output_path)
            
            if success:
                total_original += file_filter.total_packets
                total_kept += file_filter.kept_packets
                logger.info(f"File {pcap_file}: {file_filter.kept_packets}/{file_filter.total_packets} packets kept")
            else:
                logger.error(f"Failed to filter {pcap_file}")
        
        if total_original > 0:
            logger.info(f"Overall results: {total_kept}/{total_original} packets kept ({(total_kept/total_original)*100:.1f}%)")

def main():
    parser = argparse.ArgumentParser(description='Filter beacon frames and noise from WiFi PCAP files')
    parser.add_argument('input', help='Input PCAP file or directory')
    parser.add_argument('output', help='Output PCAP file or directory')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    beacon_filter = WiFiBeaconFilter()
    
    if os.path.isfile(args.input):
        # Filter single file
        success = beacon_filter.filter_pcap_file(args.input, args.output)
        if not success:
            return 1
    elif os.path.isdir(args.input):
        # Filter directory
        beacon_filter.filter_directory(args.input, args.output)
    else:
        logger.error(f"Input path {args.input} does not exist")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())