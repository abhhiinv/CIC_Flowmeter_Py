#!/usr/bin/env python3
"""Flow class - collects packets and computes CICFlowMeter features.

Each Flow object stores raw PacketInfo objects during its lifetime.
Features are computed only when the flow terminates (get_features()).
This ensures mathematical exactness for all statistics.

Active/Idle time computation follows CICFlowMeter:
  - An activity timeout threshold (default 5 seconds) separates
    active and idle periods.
  - Inter-arrival times below the threshold belong to the current
    active period; above it start a new idle period.
"""

from typing import List, Dict, Any, Optional
from .packet_info import PacketInfo
from .stats_utils import (
    safe_mean, safe_stdev, safe_variance,
    safe_min, safe_max, safe_sum, safe_div
)

# CICFlowMeter uses 5 seconds as the activity timeout threshold
ACTIVITY_TIMEOUT = 5_000_000.0  # 5 seconds in microseconds

# Ordered list of output column names - must match exactly
COLUMN_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Average Packet Size",
    "Subflow Fwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Max", "Active Min",
    "Idle Mean", "Idle Max", "Idle Min",
    "Attack Type"
]


class Flow:
    """Represents a single bidirectional network flow.
    
    Collects PacketInfo objects and computes CICFlowMeter-compatible
    features at flow termination.
    """
    
    __slots__ = (
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'fwd_packets', 'bwd_packets',
        'start_time', 'end_time', 'last_packet_time',
        'init_win_fwd', 'init_win_bwd',
        '_fwd_count', '_bwd_count',
        'label'
    )
    
    def __init__(self, src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int, protocol: str,
                 label: str = "Benign") -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.fwd_packets: List[PacketInfo] = []
        self.bwd_packets: List[PacketInfo] = []
        
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.last_packet_time: float = 0.0
        
        # Initial TCP window sizes (first packet in each direction)
        self.init_win_fwd: int = -1  # -1 means not yet set
        self.init_win_bwd: int = -1
        
        self._fwd_count: int = 0
        self._bwd_count: int = 0
        
        self.label = label
    
    @property
    def packet_count(self) -> int:
        return self._fwd_count + self._bwd_count
    
    def add_packet(self, pkt: PacketInfo) -> None:
        """Add a packet to this flow.
        
        The packet's is_forward flag must already be set by the caller.
        """
        ts = pkt.timestamp
        
        if self.packet_count == 0:
            self.start_time = ts
        
        self.end_time = ts
        self.last_packet_time = ts
        
        if pkt.is_forward:
            self.fwd_packets.append(pkt)
            self._fwd_count += 1
            # Record initial window size for forward direction
            if self.init_win_fwd == -1 and pkt.window_size > 0:
                self.init_win_fwd = pkt.window_size
        else:
            self.bwd_packets.append(pkt)
            self._bwd_count += 1
            # Record initial window size for backward direction
            if self.init_win_bwd == -1 and pkt.window_size > 0:
                self.init_win_bwd = pkt.window_size
    
    def get_duration_us(self) -> float:
        """Flow duration in microseconds."""
        return (self.end_time - self.start_time) * 1_000_000
    
    def _compute_iat(self, packets: List[PacketInfo]) -> List[float]:
        """Compute inter-arrival times in microseconds for a list of packets.
        
        Returns a list of IAT values (one less than number of packets).
        """
        if len(packets) < 2:
            return []
        timestamps = [p.timestamp for p in packets]
        return [(timestamps[i+1] - timestamps[i]) * 1_000_000
                for i in range(len(timestamps) - 1)]
    
    def _compute_active_idle(self) -> tuple:
        """Compute active and idle periods following CICFlowMeter logic.
        
        Active period: consecutive packets with IAT < ACTIVITY_TIMEOUT
        Idle period: gap between active periods (IAT >= ACTIVITY_TIMEOUT)
        
        Returns:
            (active_times, idle_times) - lists of durations in microseconds
        """
        all_pkts = sorted(self.fwd_packets + self.bwd_packets,
                          key=lambda p: p.timestamp)
        
        if len(all_pkts) < 2:
            return [], []
        
        active_times: List[float] = []
        idle_times: List[float] = []
        
        # Track start of current active period
        active_start = all_pkts[0].timestamp
        last_ts = all_pkts[0].timestamp
        
        for pkt in all_pkts[1:]:
            diff = (pkt.timestamp - last_ts) * 1_000_000  # to microseconds
            
            if diff >= ACTIVITY_TIMEOUT:
                # End current active period
                active_duration = (last_ts - active_start) * 1_000_000
                if active_duration > 0:
                    active_times.append(active_duration)
                # Record idle period
                idle_times.append(diff)
                # Start new active period
                active_start = pkt.timestamp
            
            last_ts = pkt.timestamp
        
        # Close final active period
        active_duration = (last_ts - active_start) * 1_000_000
        if active_duration > 0:
            active_times.append(active_duration)
        
        return active_times, idle_times
    
    def get_features(self) -> Dict[str, Any]:
        """Compute all CICFlowMeter features and return as ordered dict.
        
        Every feature follows CICFlowMeter definitions.
        Features that cannot be computed return 0.
        """
        # -- Gather raw values --
        
        # Forward packet lengths
        fwd_lengths = [p.packet_length for p in self.fwd_packets]
        # Backward packet lengths
        bwd_lengths = [p.packet_length for p in self.bwd_packets]
        # All packet lengths
        all_lengths = fwd_lengths + bwd_lengths
        
        # Total bytes
        total_fwd_bytes = safe_sum(fwd_lengths)
        total_bwd_bytes = safe_sum(bwd_lengths)
        total_bytes = total_fwd_bytes + total_bwd_bytes
        
        # Packet counts
        total_fwd_packets = self._fwd_count
        total_bwd_packets = self._bwd_count
        total_packets = total_fwd_packets + total_bwd_packets
        
        # Duration in microseconds (CICFlowMeter uses microseconds)
        duration_us = self.get_duration_us()
        # Duration in seconds for rate calculations
        duration_s = duration_us / 1_000_000 if duration_us > 0 else 0
        
        # -- IAT (Inter-Arrival Time) in microseconds --
        all_pkts_sorted = sorted(self.fwd_packets + self.bwd_packets,
                                  key=lambda p: p.timestamp)
        flow_iats = self._compute_iat(all_pkts_sorted)
        fwd_iats = self._compute_iat(self.fwd_packets)
        bwd_iats = self._compute_iat(self.bwd_packets)
        
        # -- Header lengths --
        # Forward header length = sum of (IP header + transport header) for each fwd packet
        fwd_header_length = sum(p.ip_header_length + p.transport_header_length
                                for p in self.fwd_packets)
        # Backward header length
        bwd_header_length = sum(p.ip_header_length + p.transport_header_length
                                for p in self.bwd_packets)
        
        # -- TCP Flag counts (across ALL packets in flow) --
        all_packets = self.fwd_packets + self.bwd_packets
        fin_count = sum(1 for p in all_packets if p.has_fin)
        psh_count = sum(1 for p in all_packets if p.has_psh)
        ack_count = sum(1 for p in all_packets if p.has_ack)
        
        # -- Forward data packets (packets with payload, excluding pure ACKs) --
        # CICFlowMeter: act_data_pkt_fwd = forward packets that carry payload
        act_data_pkt_fwd = sum(1 for p in self.fwd_packets if p.payload_length > 0)
        
        # -- Subflow Fwd Bytes = total forward payload bytes --
        subflow_fwd_bytes = sum(p.payload_length for p in self.fwd_packets)
        
        # -- min_seg_size_forward: minimum TCP segment size in forward direction --
        fwd_seg_sizes = [p.segment_size for p in self.fwd_packets
                         if p.segment_size > 0]
        min_seg_fwd = safe_min(fwd_seg_sizes) if fwd_seg_sizes else 0
        # If no segments with data, use the minimum observed header size as CICFlowMeter does
        if min_seg_fwd == 0 and self.fwd_packets:
            # CICFlowMeter uses the IP header length of the first forward packet
            # as min_seg_size_forward when there are no data segments
            min_seg_fwd = self.fwd_packets[0].ip_header_length + self.fwd_packets[0].transport_header_length
        
        # -- Initial window sizes --
        init_win_fwd = self.init_win_fwd if self.init_win_fwd != -1 else 0
        init_win_bwd = self.init_win_bwd if self.init_win_bwd != -1 else 0
        
        # -- Active / Idle times --
        active_times, idle_times = self._compute_active_idle()
        
        # -- Build feature dict in exact column order --
        features = {
            # Destination Port
            "Destination Port": self.dst_port,
            
            # Flow Duration (microseconds)
            "Flow Duration": int(duration_us),
            
            # Total Forward Packets
            "Total Fwd Packets": total_fwd_packets,
            
            # Total Length of Forward Packets (total bytes of all fwd packets)
            "Total Length of Fwd Packets": total_fwd_bytes,
            
            # Forward Packet Length statistics
            "Fwd Packet Length Max": safe_max(fwd_lengths),
            "Fwd Packet Length Min": safe_min(fwd_lengths),
            "Fwd Packet Length Mean": safe_mean(fwd_lengths),
            "Fwd Packet Length Std": safe_stdev(fwd_lengths),
            
            # Backward Packet Length statistics
            "Bwd Packet Length Max": safe_max(bwd_lengths),
            "Bwd Packet Length Min": safe_min(bwd_lengths),
            "Bwd Packet Length Mean": safe_mean(bwd_lengths),
            "Bwd Packet Length Std": safe_stdev(bwd_lengths),
            
            # Flow Bytes/s = total bytes / duration in seconds
            "Flow Bytes/s": safe_div(total_bytes, duration_s),
            
            # Flow Packets/s = total packets / duration in seconds
            "Flow Packets/s": safe_div(total_packets, duration_s),
            
            # Flow IAT statistics (microseconds)
            "Flow IAT Mean": safe_mean(flow_iats),
            "Flow IAT Std": safe_stdev(flow_iats),
            "Flow IAT Max": safe_max(flow_iats),
            "Flow IAT Min": safe_min(flow_iats),
            
            # Forward IAT statistics (microseconds)
            "Fwd IAT Total": safe_sum(fwd_iats),
            "Fwd IAT Mean": safe_mean(fwd_iats),
            "Fwd IAT Std": safe_stdev(fwd_iats),
            "Fwd IAT Max": safe_max(fwd_iats),
            "Fwd IAT Min": safe_min(fwd_iats),
            
            # Backward IAT statistics (microseconds)
            "Bwd IAT Total": safe_sum(bwd_iats),
            "Bwd IAT Mean": safe_mean(bwd_iats),
            "Bwd IAT Std": safe_stdev(bwd_iats),
            "Bwd IAT Max": safe_max(bwd_iats),
            "Bwd IAT Min": safe_min(bwd_iats),
            
            # Header lengths (sum of IP + transport headers for each packet)
            "Fwd Header Length": fwd_header_length,
            "Bwd Header Length": bwd_header_length,
            
            # Directional packet rates
            "Fwd Packets/s": safe_div(total_fwd_packets, duration_s),
            "Bwd Packets/s": safe_div(total_bwd_packets, duration_s),
            
            # Overall Packet Length statistics
            "Min Packet Length": safe_min(all_lengths),
            "Max Packet Length": safe_max(all_lengths),
            "Packet Length Mean": safe_mean(all_lengths),
            "Packet Length Std": safe_stdev(all_lengths),
            "Packet Length Variance": safe_variance(all_lengths),
            
            # TCP Flag counts
            "FIN Flag Count": fin_count,
            "PSH Flag Count": psh_count,
            "ACK Flag Count": ack_count,
            
            # Average Packet Size = total_bytes / total_packets
            "Average Packet Size": safe_div(total_bytes, total_packets),
            
            # Subflow Fwd Bytes = forward payload bytes
            "Subflow Fwd Bytes": subflow_fwd_bytes,
            
            # Initial TCP window sizes
            "Init_Win_bytes_forward": init_win_fwd,
            "Init_Win_bytes_backward": init_win_bwd,
            
            # Forward data packets (packets with payload)
            "act_data_pkt_fwd": act_data_pkt_fwd,
            
            # Minimum segment size forward
            "min_seg_size_forward": min_seg_fwd,
            
            # Active time statistics (microseconds)
            "Active Mean": safe_mean(active_times),
            "Active Max": safe_max(active_times),
            "Active Min": safe_min(active_times),
            
            # Idle time statistics (microseconds)
            "Idle Mean": safe_mean(idle_times),
            "Idle Max": safe_max(idle_times),
            "Idle Min": safe_min(idle_times),
            
            # Attack Type label (default: Benign)
            "Attack Type": self.label
        }
        
        # Ensure no NaN, None, or empty values
        for key, value in features.items():
            if key == "Attack Type":
                continue
            if value is None or (isinstance(value, float) and (value != value)):  # NaN check
                features[key] = 0
        
        return features
    
    def get_features_list(self) -> list:
        """Return features as a list in the exact COLUMN_NAMES order."""
        features = self.get_features()
        return [features[col] for col in COLUMN_NAMES]
