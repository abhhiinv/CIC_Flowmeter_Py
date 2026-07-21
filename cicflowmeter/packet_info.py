#!/usr/bin/env python3
"""PacketInfo dataclass - stores per-packet metadata extracted from raw Scapy packets.

Separates packet parsing from feature calculation per the CICFlowMeter architecture.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PacketInfo:
    """Holds extracted metadata for a single packet.
    
    All fields are populated at parse time from a Scapy packet.
    The Flow object stores lists of PacketInfo and computes features
    only at flow termination.
    """
    # Timing
    timestamp: float = 0.0  # epoch seconds (float for sub-second precision)
    
    # Addressing
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0  # IP protocol number (6=TCP, 17=UDP)
    protocol_str: str = ""  # human readable e.g. "TCP", "UDP"
    
    # Sizes
    packet_length: int = 0        # total length of the packet (len(packet))
    ip_header_length: int = 0     # IP header length in bytes
    transport_header_length: int = 0  # TCP/UDP header length in bytes
    payload_length: int = 0       # application payload length in bytes
    segment_size: int = 0         # TCP segment size (payload only)
    
    # TCP specific
    tcp_flags: int = 0            # raw TCP flags bitmask
    tcp_flags_str: str = ""       # string representation of flags
    has_fin: bool = False
    has_syn: bool = False
    has_rst: bool = False
    has_psh: bool = False
    has_ack: bool = False
    has_urg: bool = False
    has_ece: bool = False
    has_cwr: bool = False
    window_size: int = 0          # TCP window size
    seq_number: int = 0           # TCP sequence number
    ack_number: int = 0           # TCP acknowledgement number
    
    # Direction (set by FlowManager when adding to a flow)
    is_forward: bool = True
