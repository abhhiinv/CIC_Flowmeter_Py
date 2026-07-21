#!/usr/bin/env python3
"""FlowKey - bidirectional 5-tuple flow identifier.

Flows are identified using the bidirectional 5-tuple:
  (src_ip, dst_ip, src_port, dst_port, protocol)
Packets in the reverse direction map to the same flow.
"""

from typing import Tuple


class FlowKey:
    """Represents a unique bidirectional network flow identifier.
    
    The key is normalised so that the smaller (IP, port) pair always
    comes first, making forward and reverse packets hash to the same key.
    """
    
    __slots__ = ('ip_a', 'port_a', 'ip_b', 'port_b', 'protocol',
                 'src_ip', 'src_port', 'dst_ip', 'dst_port')
    
    def __init__(self, src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int, protocol: str) -> None:
        # Store original source/destination for direction detection
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        
        # Normalise: smaller (ip, port) tuple is always 'A'
        if (src_ip, src_port) <= (dst_ip, dst_port):
            self.ip_a, self.port_a = src_ip, src_port
            self.ip_b, self.port_b = dst_ip, dst_port
        else:
            self.ip_a, self.port_a = dst_ip, dst_port
            self.ip_b, self.port_b = src_ip, src_port
        
        self.protocol = protocol
    
    def is_forward(self, src_ip: str, src_port: int) -> bool:
        """Return True if a packet with (src_ip, src_port) is in the forward direction.
        
        Forward = same direction as the first packet that created this flow.
        The first packet's source is stored as src_ip/src_port.
        """
        return src_ip == self.src_ip and src_port == self.src_port
    
    @property
    def tuple(self) -> Tuple[str, int, str, int, str]:
        return (self.ip_a, self.port_a, self.ip_b, self.port_b, self.protocol)
    
    def __hash__(self) -> int:
        return hash(self.tuple)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FlowKey):
            return NotImplemented
        return self.tuple == other.tuple
    
    def __repr__(self) -> str:
        return (f"FlowKey({self.ip_a}:{self.port_a} <-> "
                f"{self.ip_b}:{self.port_b} [{self.protocol}])")
