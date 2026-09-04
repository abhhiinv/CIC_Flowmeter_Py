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
    Returns None if the packet cannot be parsed (no IP layer, or no
    recognisable transport layer).
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
        # IP header length: ihl is in 32-bit words; default to 5 (20 bytes) if unset
        ihl = ip_layer.ihl
        pkt.ip_header_length = (ihl * 4) if ihl else 20
        # packet_length = total IP packet length (header + payload)
        ip_len = ip_layer.len
        pkt.packet_length = ip_len if ip_len else len(bytes(raw_packet[IP]))
    elif raw_packet.haslayer(IPv6):
        ipv6_layer = raw_packet[IPv6]
        pkt.src_ip = ipv6_layer.src
        pkt.dst_ip = ipv6_layer.dst
        pkt.ip_header_length = 40  # IPv6 fixed header is always 40 bytes
        # plen = payload length (everything after the 40-byte fixed header)
        pkt.packet_length = 40 + (ipv6_layer.plen if ipv6_layer.plen else 0)
        # Walk the next-header chain to find the actual transport protocol.
        # IPv6 extension headers (routing=43, fragment=44, hop-by-hop=0,
        # dest-options=60, etc.) sit between the IPv6 header and TCP/UDP.
        # Scapy exposes the innermost TCP/UDP layer directly via haslayer().
        if raw_packet.haslayer(TCP):
            pkt.protocol = 6
        elif raw_packet.haslayer(UDP):
            pkt.protocol = 17
        else:
            pkt.protocol = ipv6_layer.nh  # fallback for other protocols
    else:
        # Skip non-IP packets (ARP, etc.) - CICFlowMeter only processes IP
        return None
    
    # -- Transport layer --
    if raw_packet.haslayer(TCP):
        tcp_layer = raw_packet[TCP]
        pkt.src_port = tcp_layer.sport
        pkt.dst_port = tcp_layer.dport
        pkt.protocol_str = "TCP"
        
        # TCP header length: dataofs field is in 32-bit words (minimum 5 = 20 bytes)
        pkt.transport_header_length = (tcp_layer.dataofs * 4
                                       if tcp_layer.dataofs and tcp_layer.dataofs >= 5
                                       else 20)
        
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
        
        # Payload length = total packet length - IP header - TCP header
        pkt.payload_length = max(0,
            pkt.packet_length - pkt.ip_header_length - pkt.transport_header_length)
        pkt.segment_size = pkt.payload_length
        
    elif raw_packet.haslayer(UDP):
        udp_layer = raw_packet[UDP]
        pkt.src_port = udp_layer.sport
        pkt.dst_port = udp_layer.dport
        pkt.protocol_str = "UDP"
        pkt.transport_header_length = 8  # UDP header is always 8 bytes
        
        # Payload length = total packet length - IP header - UDP header
        pkt.payload_length = max(0,
            pkt.packet_length - pkt.ip_header_length - 8)
        pkt.segment_size = pkt.payload_length
    else:
        # Other protocols (ICMP, etc.) - no ports, no transport header
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
