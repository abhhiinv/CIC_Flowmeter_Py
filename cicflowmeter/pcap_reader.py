#!/usr/bin/env python3
"""PCAPReader - reads PCAP files using Scapy and yields PacketInfo objects.

Separates packet parsing from feature calculation.
Supports streaming (PcapReader) for constant-memory processing of large files.
"""

import logging
from typing import Iterator, Optional

from scapy.all import PcapReader as ScapyPcapReader, rdpcap, IP, IPv6, TCP, UDP

from .packet_info import PacketInfo

logger = logging.getLogger(__name__)


def parse_packet(raw_packet) -> Optional[PacketInfo]:
    """Parse a Scapy packet into a PacketInfo dataclass.
    
    Extracts all fields needed for CICFlowMeter feature computation.
    Returns None if the packet cannot be parsed (no IP layer).
    """
    pkt = PacketInfo()
    
    # -- Timestamp --
    pkt.timestamp = float(raw_packet.time)
    
    # -- IP layer --
    if raw_packet.haslayer(IP):
        ip_layer = raw_packet[IP]
        pkt.src_ip = ip_layer.src
        pkt.dst_ip = ip_layer.dst
        pkt.protocol = ip_layer.proto
        # IP header length: ihl field is in 32-bit words
        pkt.ip_header_length = ip_layer.ihl * 4
        pkt.packet_length = ip_layer.len  # Total IP packet length
    elif raw_packet.haslayer(IPv6):
        ipv6_layer = raw_packet[IPv6]
        pkt.src_ip = ipv6_layer.src
        pkt.dst_ip = ipv6_layer.dst
        pkt.protocol = ipv6_layer.nh  # next header
        pkt.ip_header_length = 40  # IPv6 fixed header is 40 bytes
        pkt.packet_length = 40 + ipv6_layer.plen
    else:
        # Skip non-IP packets (ARP, etc.) - CICFlowMeter only processes IP
        return None
    
    # -- Transport layer --
    if raw_packet.haslayer(TCP):
        tcp_layer = raw_packet[TCP]
        pkt.src_port = tcp_layer.sport
        pkt.dst_port = tcp_layer.dport
        pkt.protocol_str = "TCP"
        
        # TCP header length: dataofs field is in 32-bit words
        pkt.transport_header_length = tcp_layer.dataofs * 4 if tcp_layer.dataofs else 20
        
        # TCP flags
        flags = tcp_layer.flags
        pkt.tcp_flags = int(flags)
        pkt.tcp_flags_str = str(flags)
        pkt.has_fin = bool(flags & 0x01)  # FIN
        pkt.has_syn = bool(flags & 0x02)  # SYN
        pkt.has_rst = bool(flags & 0x04)  # RST
        pkt.has_psh = bool(flags & 0x08)  # PSH
        pkt.has_ack = bool(flags & 0x10)  # ACK
        pkt.has_urg = bool(flags & 0x20)  # URG
        pkt.has_ece = bool(flags & 0x40)  # ECE
        pkt.has_cwr = bool(flags & 0x80)  # CWR
        
        # Window size
        pkt.window_size = tcp_layer.window
        
        # Sequence and acknowledgement numbers
        pkt.seq_number = tcp_layer.seq
        pkt.ack_number = tcp_layer.ack
        
        # Payload length = total IP length - IP header - TCP header
        pkt.payload_length = max(0, pkt.packet_length - pkt.ip_header_length - pkt.transport_header_length)
        # Segment size = same as payload length for TCP
        pkt.segment_size = pkt.payload_length
        
    elif raw_packet.haslayer(UDP):
        udp_layer = raw_packet[UDP]
        pkt.src_port = udp_layer.sport
        pkt.dst_port = udp_layer.dport
        pkt.protocol_str = "UDP"
        pkt.transport_header_length = 8  # UDP header is always 8 bytes
        
        # Payload length = total IP length - IP header - UDP header
        pkt.payload_length = max(0, pkt.packet_length - pkt.ip_header_length - 8)
        pkt.segment_size = pkt.payload_length
    else:
        # Other protocols (ICMP, etc.) - set port to 0
        pkt.src_port = 0
        pkt.dst_port = 0
        pkt.protocol_str = f"OTHER_{pkt.protocol}"
        pkt.transport_header_length = 0
        pkt.payload_length = max(0, pkt.packet_length - pkt.ip_header_length)
    
    return pkt


def read_pcap_streaming(pcap_file: str) -> Iterator[PacketInfo]:
    """Read a PCAP file using streaming (PcapReader) and yield PacketInfo objects.
    
    Memory-efficient: processes one packet at a time.
    Suitable for multi-GB PCAP files.
    """
    try:
        with ScapyPcapReader(pcap_file) as reader:
            for raw_packet in reader:
                pkt = parse_packet(raw_packet)
                if pkt is not None:
                    yield pkt
    except Exception as e:
        logger.error(f"Error reading PCAP file {pcap_file}: {e}")
        return


def read_pcap_nonstreaming(pcap_file: str) -> Iterator[PacketInfo]:
    """Read a PCAP file using rdpcap (loads all into memory) and yield PacketInfo.
    
    Faster for smaller files but uses more memory.
    """
    try:
        packets = rdpcap(pcap_file)
        for raw_packet in packets:
            pkt = parse_packet(raw_packet)
            if pkt is not None:
                yield pkt
    except Exception as e:
        logger.error(f"Error reading PCAP file {pcap_file}: {e}")
        return
