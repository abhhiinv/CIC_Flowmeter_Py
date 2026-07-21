#!/usr/bin/env python3
"""FlowManager - manages active flows, handles timeouts, yields completed flows.

Each flow expires after an inactivity timeout of 120 seconds.
Completed flows are yielded immediately to enable streaming CSV export
and constant-memory processing.
"""

import logging
from typing import Dict, Iterator, List, Optional

from .flow_key import FlowKey
from .flow import Flow
from .packet_info import PacketInfo

logger = logging.getLogger(__name__)

# Flow inactivity timeout in seconds (CICFlowMeter default)
FLOW_TIMEOUT_SECONDS = 120.0


class FlowManager:
    """Manages active bidirectional flows and handles flow expiration.
    
    Packets are added one at a time. The manager:
    1. Identifies the flow (bidirectional 5-tuple)
    2. Creates new flows or adds to existing ones
    3. Checks for timed-out flows and yields them as completed
    4. At the end, all remaining active flows are flushed
    """
    
    def __init__(self, timeout: float = FLOW_TIMEOUT_SECONDS,
                 label: str = "Benign") -> None:
        self.timeout = timeout
        self.label = label
        self.active_flows: Dict[FlowKey, Flow] = {}
        self.flow_count: int = 0
        self.packet_count: int = 0
    
    def _make_flow_key(self, pkt: PacketInfo) -> FlowKey:
        """Create a FlowKey from a PacketInfo."""
        return FlowKey(
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            protocol=pkt.protocol_str
        )
    
    def add_packet(self, pkt: PacketInfo) -> List[Flow]:
        """Add a packet and return any flows that have timed out.
        
        Returns a list of completed (timed-out) flows that were evicted.
        The caller should extract features from these flows and write to CSV.
        """
        self.packet_count += 1
        completed_flows: List[Flow] = []
        
        # First, check for timed-out flows based on current packet time
        completed_flows.extend(self._check_timeouts(pkt.timestamp))
        
        # Find or create the flow
        flow_key = self._make_flow_key(pkt)
        
        if flow_key not in self.active_flows:
            # Create new flow - the first packet defines forward direction
            flow = Flow(
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol_str,
                label=self.label
            )
            self.active_flows[flow_key] = flow
            self.flow_count += 1
        
        flow = self.active_flows[flow_key]
        
        # Determine direction: forward if packet source matches the flow's original source
        pkt.is_forward = (pkt.src_ip == flow.src_ip and pkt.src_port == flow.src_port)
        
        # Add packet to flow
        flow.add_packet(pkt)
        
        return completed_flows
    
    def _check_timeouts(self, current_time: float) -> List[Flow]:
        """Check for flows that have exceeded the inactivity timeout.
        
        A flow times out if:
            current_time - flow.last_packet_time > timeout
        
        Returns a list of timed-out flows (removed from active_flows).
        """
        timed_out: List[Flow] = []
        keys_to_remove: List[FlowKey] = []
        
        for key, flow in self.active_flows.items():
            if flow.last_packet_time > 0:  # flow has at least one packet
                idle_time = current_time - flow.last_packet_time
                if idle_time > self.timeout:
                    timed_out.append(flow)
                    keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.active_flows[key]
        
        return timed_out
    
    def flush_all(self) -> List[Flow]:
        """Flush all remaining active flows.
        
        Called at the end of PCAP processing to finalize all flows.
        Returns all active flows and clears the manager.
        """
        remaining = list(self.active_flows.values())
        self.active_flows.clear()
        return remaining
    
    def get_stats(self) -> dict:
        """Return summary statistics about the flow manager state."""
        return {
            'total_packets_processed': self.packet_count,
            'total_flows_created': self.flow_count,
            'active_flows': len(self.active_flows)
        }
