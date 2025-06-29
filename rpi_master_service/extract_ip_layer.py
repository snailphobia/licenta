#!/usr/bin/env python3
"""
WiFi PCAP Analyzer and Layer 3 Extractor with detailed frame analysis
"""

import struct
import time
import logging
import os
import sys
import argparse
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WiFiPCAPProcessor:
    def __init__(self):
        self.processed_packets = 0
        self.skipped_packets = 0
        self.total_packets = 0
        self.frame_type_stats = {}
        self.ssid_stats = {}
        
    def write_pcap_global_header(self, pcap_file):
        """Write PCAP global header for Ethernet (Layer 2)."""
        pcap_file.write(struct.pack(
            '!IHHIIII',
            0xa1b2c3d4,  # magic_number
            2,           # version_major
            4,           # version_minor
            0,           # thiszone (GMT to local correction)
            0,           # sigfigs (accuracy of timestamps)
            65535,       # snaplen (max length of captured packets)
            1            # network (LINKTYPE_ETHERNET)
        ))
    
    def write_pcap_packet(self, pcap_file, packet_data, timestamp_sec, timestamp_usec):
        """Write a PCAP packet record."""
        pcap_file.write(struct.pack(
            '!IIII',
            timestamp_sec,    # ts_sec (timestamp seconds)
            timestamp_usec,   # ts_usec (timestamp microseconds)
            len(packet_data), # incl_len (number of octets saved in file)
            len(packet_data)  # orig_len (actual length of packet)
        ))
        pcap_file.write(packet_data)
    
    def read_pcap_global_header(self, pcap_file):
        """Read and validate PCAP global header."""
        header = pcap_file.read(24)
        if len(header) != 24:
            return False
            
        magic, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack('!IHHIIII', header)
        
        if magic != 0xa1b2c3d4:
            logger.error("Invalid PCAP magic number")
            return False
            
        logger.info(f"PCAP header: version={version_major}.{version_minor}, network={network}")
        return True
    
    def read_pcap_packet(self, pcap_file):
        """Read a single packet from PCAP file."""
        # Read packet header (16 bytes)
        packet_header = pcap_file.read(16)
        if len(packet_header) != 16:
            return None  # End of file
            
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('!IIII', packet_header)
        
        # Read packet data
        packet_data = pcap_file.read(incl_len)
        if len(packet_data) != incl_len:
            logger.error("Truncated packet data")
            return None
            
        return ts_sec, ts_usec, packet_data
    
    def parse_radiotap_header(self, data):
        """Parse Radiotap header and return its length."""
        if len(data) < 4:
            return 0
            
        try:
            # Radiotap header: version(1) + pad(1) + length(2) + present(4+)
            version, pad, radiotap_len = struct.unpack('<BBH', data[0:4])
            logger.debug(f"Radiotap: version={version}, pad={pad}, length={radiotap_len}")
            return radiotap_len
        except struct.error:
            return 0
    
    def extract_ssid_from_beacon(self, data, offset=0):
        """Extract SSID from beacon frame."""
        try:
            # Look for SSID element (Tag 0)
            i = offset
            while i < len(data) - 2:
                tag = data[i]
                length = data[i + 1]
                
                if tag == 0 and length > 0 and i + 2 + length <= len(data):
                    # Found SSID
                    ssid = data[i + 2:i + 2 + length].decode('utf-8', errors='ignore')
                    return ssid
                
                i += 2 + length
                
        except Exception as e:
            logger.debug(f"Error extracting SSID: {e}")
            
        return None
    
    def parse_80211_header(self, data):
        """
        Parse 802.11 header and provide detailed analysis.
        Returns (header_length, payload, frame_info) with comprehensive frame information.
        """
        if len(data) < 24:  # Minimum 802.11 header size
            logger.debug(f"802.11 frame too short: {len(data)} bytes")
            return 0, None, None
            
        # Parse Frame Control (first 2 bytes)
        frame_control = struct.unpack('<H', data[0:2])[0]
        
        frame_type = (frame_control >> 2) & 0x3
        frame_subtype = (frame_control >> 4) & 0xF
        to_ds = (frame_control >> 8) & 0x1
        from_ds = (frame_control >> 9) & 0x1
        more_frag = (frame_control >> 10) & 0x1
        retry = (frame_control >> 11) & 0x1
        pwr_mgt = (frame_control >> 12) & 0x1
        more_data = (frame_control >> 13) & 0x1
        protected = (frame_control >> 14) & 0x1
        order = (frame_control >> 15) & 0x1
        
        # Frame type and subtype descriptions
        frame_types = {
            0: "Management",
            1: "Control", 
            2: "Data",
            3: "Reserved"
        }
        
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
        
        data_subtypes = {
            0: "Data",
            1: "Data + CF-Ack",
            2: "Data + CF-Poll", 
            3: "Data + CF-Ack + CF-Poll",
            4: "Null",
            8: "QoS Data",
            12: "QoS Null"
        }
        
        frame_type_name = frame_types.get(frame_type, f"Unknown({frame_type})")
        
        if frame_type == 0:  # Management
            subtype_name = mgmt_subtypes.get(frame_subtype, f"Unknown Mgmt({frame_subtype})")
        elif frame_type == 2:  # Data
            subtype_name = data_subtypes.get(frame_subtype, f"Unknown Data({frame_subtype})")
        else:
            subtype_name = f"Subtype {frame_subtype}"
            
        frame_info = {
            'type': frame_type,
            'subtype': frame_subtype,
            'type_name': frame_type_name,
            'subtype_name': subtype_name,
            'to_ds': to_ds,
            'from_ds': from_ds,
            'protected': protected,
            'ssid': None
        }
        
        # Track frame types for statistics
        key = f"{frame_type_name} - {subtype_name}"
        self.frame_type_stats[key] = self.frame_type_stats.get(key, 0) + 1
        
        logger.debug(f"802.11 Frame: {key}, to_ds={to_ds}, from_ds={from_ds}, protected={protected}")
        
        # Extract SSID from beacon frames
        if frame_type == 0 and frame_subtype == 8:  # Beacon frame
            ssid = self.extract_ssid_from_beacon(data, 36)  # Skip fixed parameters
            if ssid:
                frame_info['ssid'] = ssid
                self.ssid_stats[ssid] = self.ssid_stats.get(ssid, 0) + 1
                logger.debug(f"Beacon frame SSID: {ssid}")
        
        # We only want data frames (type 2) that are not protected (encrypted)
        if frame_type != 2:
            logger.debug(f"Skipping non-data frame: {key}")
            return 0, None, frame_info
            
        # Skip encrypted frames for now
        if protected:
            logger.debug("Skipping encrypted data frame")
            return 0, None, frame_info
            
        # Calculate header length based on frame type and flags
        header_len = 24  # Base header length
        
        # Address 4 present if both ToDS and FromDS are set (WDS)
        if to_ds and from_ds:
            header_len += 6
            logger.debug("WDS frame detected, adding 6 bytes for Address 4")
            
        # Check for QoS field (subtype 8-15 are QoS data frames)
        if frame_subtype >= 8:
            header_len += 2
            logger.debug("QoS frame detected, adding 2 bytes")
            
        # Check for HT Control field (order bit set)
        if order:
            header_len += 4
            logger.debug("HT Control field detected, adding 4 bytes")
            
        if len(data) < header_len:
            logger.debug(f"Frame too short for calculated header length: {len(data)} < {header_len}")
            return 0, None, frame_info
            
        payload = data[header_len:]
        logger.debug(f"802.11 data payload length: {len(payload)}")
        
        if len(payload) < 8:
            logger.debug("Data payload too short for LLC/SNAP header")
            return 0, None, frame_info
            
        # Debug: show first 16 bytes of payload
        logger.debug(f"Data payload start: {payload[:16].hex()}")
        
        # Look for LLC/SNAP header indicating IP packet
        # LLC: AA AA 03, SNAP: 00 00 00 followed by EtherType
        if payload[0:3] == b'\xaa\xaa\x03':
            logger.debug("Found LLC header (AA AA 03)")
            if len(payload) >= 8 and payload[3:6] == b'\x00\x00\x00':
                # Extract EtherType (bytes 6-7)
                ethertype = struct.unpack('>H', payload[6:8])[0]
                logger.debug(f"Found SNAP header with EtherType: 0x{ethertype:04x}")
                
                # Check for IP (0x0800) or IPv6 (0x86dd) or ARP (0x0806)
                if ethertype in [0x0800, 0x86dd, 0x0806]:
                    logger.debug(f"Valid EtherType found: 0x{ethertype:04x}")
                    # Return payload after LLC/SNAP header
                    return header_len, payload[8:], frame_info
                else:
                    logger.debug(f"Unknown EtherType: 0x{ethertype:04x}")
            else:
                # Non-standard SNAP header - let's examine what's inside
                snap_oui = payload[3:6].hex()
                logger.debug(f"Non-standard SNAP header: {snap_oui}")
                
                # Check if payload after SNAP header looks like IP
                if len(payload) >= 12:  # Allow for 8-byte LLC/SNAP + minimum IP header
                    # Look at bytes after the 8-byte LLC/SNAP header
                    post_snap_payload = payload[8:]
                    if len(post_snap_payload) >= 4:
                        version = (post_snap_payload[0] >> 4) & 0xF
                        if version == 4:
                            logger.debug("Found IPv4 packet after non-standard SNAP header")
                            return header_len, post_snap_payload, frame_info
                        elif version == 6:
                            logger.debug("Found IPv6 packet after non-standard SNAP header")
                            return header_len, post_snap_payload, frame_info
                        else:
                            logger.debug(f"Non-IP data after SNAP header, first 8 bytes: {post_snap_payload[:8].hex()}")
                
                # Try looking at the raw payload without SNAP assumptions
                if len(payload) >= 10:
                    for offset in [6, 8, 10, 12]:  # Try different offsets
                        if offset < len(payload):
                            test_payload = payload[offset:]
                            if len(test_payload) >= 4:
                                version = (test_payload[0] >> 4) & 0xF
                                if version == 4:
                                    logger.debug(f"Found IPv4 packet at offset {offset}")
                                    return header_len, test_payload, frame_info
                                elif version == 6:
                                    logger.debug(f"Found IPv6 packet at offset {offset}")
                                    return header_len, test_payload, frame_info
        else:
            # Try to detect IP packets directly (without LLC/SNAP)
            if len(payload) >= 20:  # Minimum IP header size
                version = (payload[0] >> 4) & 0xF
                if version == 4:
                    logger.debug("Found IPv4 packet without LLC/SNAP")
                    return header_len, payload, frame_info
                elif version == 6:
                    logger.debug("Found IPv6 packet without LLC/SNAP")
                    return header_len, payload, frame_info
            
            logger.debug(f"No IP payload found, payload starts with: {payload[0:8].hex()}")
                
        return 0, None, frame_info
    
    def create_ethernet_frame(self, ip_packet, ethertype=0x0800):
        """Create a fake Ethernet frame around the IP packet."""
        # Create fake MAC addresses
        dst_mac = b'\x00\x00\x00\x00\x00\x01'  # Fake destination MAC
        src_mac = b'\x00\x00\x00\x00\x00\x02'  # Fake source MAC
        
        # Determine EtherType based on IP version
        if len(ip_packet) > 0:
            version = (ip_packet[0] >> 4) & 0xF
            if version == 4:
                ethertype = 0x0800  # IPv4
            elif version == 6:
                ethertype = 0x86dd  # IPv6
            else:
                # Check if it's ARP by looking at the first few bytes
                if len(ip_packet) >= 8:
                    try:
                        # ARP has hardware type (2 bytes), protocol type (2 bytes)
                        hw_type, proto_type = struct.unpack('>HH', ip_packet[0:4])
                        if hw_type == 1 and proto_type == 0x0800:  # Ethernet + IP
                            ethertype = 0x0806  # ARP
                    except:
                        pass
        
        # Create Ethernet header (14 bytes)
        eth_header = dst_mac + src_mac + struct.pack('>H', ethertype)
        
        return eth_header + ip_packet
    
    def analyze_pcap_file(self, input_file):
        """Analyze PCAP file and show detailed statistics."""
        logger.info(f"Analyzing {input_file}")
        
        try:
            with open(input_file, 'rb') as infile:
                # Read input PCAP header
                if not self.read_pcap_global_header(infile):
                    logger.error(f"Failed to read PCAP header from {input_file}")
                    return False
                
                # Process packets for analysis
                while True:
                    packet_info = self.read_pcap_packet(infile)
                    if packet_info is None:
                        break  # End of file
                        
                    ts_sec, ts_usec, packet_data = packet_info
                    self.total_packets += 1
                    
                    logger.debug(f"\n--- Packet {self.total_packets} ---")
                    
                    # Parse Radiotap header
                    radiotap_len = self.parse_radiotap_header(packet_data)
                    if radiotap_len == 0 or radiotap_len >= len(packet_data):
                        logger.debug(f"Invalid Radiotap length: {radiotap_len}")
                        self.skipped_packets += 1
                        continue
                    
                    # Get 802.11 frame (after Radiotap)
                    wifi_frame = packet_data[radiotap_len:]
                    
                    # Parse 802.11 header
                    header_len, ip_payload, frame_info = self.parse_80211_header(wifi_frame)
                    if ip_payload is not None and len(ip_payload) > 0:
                        self.processed_packets += 1
                        logger.info(f"Packet {self.total_packets}: Found IP data ({len(ip_payload)} bytes)")
                    else:
                        self.skipped_packets += 1
                        if frame_info:
                            ssid_info = f" SSID: {frame_info['ssid']}" if frame_info.get('ssid') else ""
                            logger.info(f"Packet {self.total_packets}: {frame_info['type_name']} - {frame_info['subtype_name']}{ssid_info}")
                
                # Print comprehensive statistics
                print("\n" + "="*80)
                print("WIFI PCAP ANALYSIS RESULTS")
                print("="*80)
                print(f"Total packets analyzed: {self.total_packets}")
                print(f"IP data packets found: {self.processed_packets}")
                print(f"Non-IP packets: {self.skipped_packets}")
                print(f"Success rate: {(self.processed_packets/self.total_packets)*100:.1f}%")
                
                print(f"\nFrame Type Breakdown:")
                for frame_type, count in sorted(self.frame_type_stats.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / self.total_packets) * 100
                    print(f"  {frame_type}: {count} ({percentage:.1f}%)")
                
                if self.ssid_stats:
                    print(f"\nSSIDs Detected:")
                    for ssid, count in sorted(self.ssid_stats.items(), key=lambda x: x[1], reverse=True):
                        percentage = (count / self.total_packets) * 100
                        print(f"  '{ssid}': {count} beacons ({percentage:.1f}%)")
                
                print("="*80)
                
                return True
                
        except Exception as e:
            logger.error(f"Error analyzing {input_file}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def process_pcap_file(self, input_file, output_file):
        """Process a single PCAP file and extract Layer 3 packets."""
        logger.info(f"Processing {input_file} -> {output_file}")
        
        # First analyze the file
        if not self.analyze_pcap_file(input_file):
            return False
        
        # Reset counters for processing
        self.processed_packets = 0
        self.skipped_packets = 0
        self.total_packets = 0
        
        try:
            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Read input PCAP header
                if not self.read_pcap_global_header(infile):
                    logger.error(f"Failed to read PCAP header from {input_file}")
                    return False
                
                # Write output PCAP header (Ethernet)
                self.write_pcap_global_header(outfile)
                
                # Process packets
                while True:
                    packet_info = self.read_pcap_packet(infile)
                    if packet_info is None:
                        break  # End of file
                        
                    ts_sec, ts_usec, packet_data = packet_info
                    self.total_packets += 1
                    
                    # Parse Radiotap header
                    radiotap_len = self.parse_radiotap_header(packet_data)
                    if radiotap_len == 0 or radiotap_len >= len(packet_data):
                        self.skipped_packets += 1
                        continue
                    
                    # Get 802.11 frame (after Radiotap)
                    wifi_frame = packet_data[radiotap_len:]
                    
                    # Parse 802.11 header and extract IP payload
                    header_len, ip_payload, frame_info = self.parse_80211_header(wifi_frame)
                    if ip_payload is None or len(ip_payload) == 0:
                        self.skipped_packets += 1
                        continue
                    
                    # Create Ethernet frame around IP packet
                    ethernet_frame = self.create_ethernet_frame(ip_payload)
                    
                    # Write to output PCAP
                    self.write_pcap_packet(outfile, ethernet_frame, ts_sec, ts_usec)
                    self.processed_packets += 1
                
                logger.info(f"Extraction complete: {self.processed_packets} IP packets extracted from {self.total_packets} total packets")
                return True
                
        except Exception as e:
            logger.error(f"Error processing {input_file}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

def main():
    parser = argparse.ArgumentParser(description='Analyze and extract Layer 3 packets from WiFi PCAP files')
    parser.add_argument('input', help='Input PCAP file')
    parser.add_argument('output', nargs='?', help='Output PCAP file (optional, for analysis only)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--analyze-only', action='store_true', help='Only analyze, do not extract')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    processor = WiFiPCAPProcessor()
    
    if args.analyze_only or not args.output:
        # Analysis only
        processor.analyze_pcap_file(args.input)
    else:
        # Analysis and extraction
        success = processor.process_pcap_file(args.input, args.output)
        if not success:
            return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())