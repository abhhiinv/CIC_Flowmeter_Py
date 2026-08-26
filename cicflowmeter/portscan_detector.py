#!/usr/bin/env python3
"""PortScanDetector - cross-flow port scan detection.

Per-flow ML cannot detect port scans because each individual probe flow looks
like normal traffic (a single SYN + RST/SYN-ACK pair has no distinguishing
features). Port scans are only visible when you look across many flows from
the same source in a short time window.

Algorithm:
    For each completed flow, record (dst_ip, dst_port) as a unique "probe"
    for the source IP. After a configurable window, if the number of unique
    (dst_ip, dst_port) probes from a single source IP exceeds a threshold,
    flag it as a port scan.

    State transitions:
        - Returns is_new_episode=True only on the 0→1 crossing (threshold first
          reached). Subsequent flows from the same src_ip while still in the
          window return is_new_episode=False so callers can avoid spamming
          duplicate alerts for a single scan episode.
        - When probe count drops back below threshold (entries age out of the
          window), the src_ip is removed from alerting state so the next scan
          episode triggers a fresh alert.

    Clock consistency:
        - Both record_and_check() and evict_stale() use flow_end_time (packet
          timestamps) as their reference clock — not wall-clock time. This
          avoids inconsistencies when flows are processed with lag (e.g. after
          a capture backlog), where wall-clock time would be ahead of packet
          time, causing overly aggressive eviction.
"""

import logging
from collections import defaultdict
from typing import Dict, Set, Tuple

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_WINDOW_SECONDS = 60.0    # Sliding window to count unique port contacts
DEFAULT_PORT_THRESHOLD = 30      # Unique (dst_ip, dst_port) probes = port scan


class PortScanDetector:
    """Detects port scans by tracking unique (dst_ip, dst_port) contacts per
    source IP within a sliding time window.

    Thread-safety: this class is NOT thread-safe. It is designed to be called
    from the single main-thread flow-processing loop in main.py.
    """

    def __init__(self,
                 window_seconds: float = DEFAULT_WINDOW_SECONDS,
                 port_threshold: int = DEFAULT_PORT_THRESHOLD) -> None:
        """
        Args:
            window_seconds: Sliding time window to count probe contacts.
            port_threshold: Number of unique (dst_ip, dst_port) contacts from
                            one source IP within the window before flagging as
                            port scan.
        """
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold

        # src_ip -> list of (flow_end_time, dst_ip, dst_port) tuples
        self._probe_log: Dict[str, list] = defaultdict(list)

        # src_ips currently above threshold (in an active scan episode)
        self._alerting: Set[str] = set()

        # Latest flow_end_time seen across all calls — used as the reference
        # clock for evict_stale() so both entry points share the same timeline.
        self._latest_time: float = 0.0

    def record_and_check(self,
                         src_ip: str,
                         dst_ip: str,
                         dst_port: int,
                         flow_end_time: float) -> Tuple[bool, bool, int]:
        """Record a completed flow as a probe and check if src_ip is scanning.

        Args:
            src_ip:         Source IP of the completed flow.
            dst_ip:         Destination IP of the completed flow.
            dst_port:       Destination port of the completed flow.
            flow_end_time:  Packet timestamp when the flow ended (flow.end_time).
                            Used as the reference clock — NOT wall-clock time —
                            so this stays consistent with evict_stale().

        Returns:
            (is_scan, is_new_episode, unique_port_count):
                is_scan          — True if src_ip is currently port-scanning.
                is_new_episode   — True only on the 0→1 threshold crossing
                                   (first flow that pushes src_ip over the
                                   threshold). False for all subsequent flows
                                   while the episode is ongoing.
                unique_port_count — Number of unique (dst_ip, dst_port) probes
                                   seen from src_ip in the current window.
        """
        # Advance the shared reference clock
        if flow_end_time > self._latest_time:
            self._latest_time = flow_end_time

        cutoff = flow_end_time - self.window_seconds

        # Append current probe
        self._probe_log[src_ip].append((flow_end_time, dst_ip, dst_port))

        # Evict entries older than the window (using packet time as reference)
        self._probe_log[src_ip] = [
            entry for entry in self._probe_log[src_ip]
            if entry[0] >= cutoff
        ]

        # Count unique (dst_ip, dst_port) combinations in window
        unique_probes: Set[Tuple[str, int]] = {
            (entry[1], entry[2]) for entry in self._probe_log[src_ip]
        }
        unique_count = len(unique_probes)
        is_scan = unique_count >= self.port_threshold

        # --- State transition logic ---
        # Only fire is_new_episode on the 0→1 edge, not on every subsequent
        # flow while the scan is ongoing. Reset state when count drops back
        # below threshold so the next scan episode triggers a fresh alert.
        if is_scan:
            if src_ip not in self._alerting:
                # First crossing: new episode
                self._alerting.add(src_ip)
                is_new_episode = True
                logger.info(
                    f"Port scan detected: {src_ip} contacted {unique_count} "
                    f"unique (dst_ip, port) pairs in the last "
                    f"{self.window_seconds:.0f}s — new episode"
                )
            else:
                # Ongoing episode, already alerted
                is_new_episode = False
                logger.debug(
                    f"Port scan ongoing: {src_ip} at {unique_count} unique "
                    f"ports (episode already active)"
                )
        else:
            if src_ip in self._alerting:
                # Scan episode ended (entries aged out below threshold)
                self._alerting.discard(src_ip)
                logger.info(
                    f"Port scan episode ended for {src_ip} "
                    f"(unique ports now {unique_count} < {self.port_threshold})"
                )
            is_new_episode = False

        return is_scan, is_new_episode, unique_count

    def evict_stale(self) -> None:
        """Purge all probe logs older than the window.

        Uses self._latest_time (the most recent flow_end_time seen by
        record_and_check) as the reference clock — NOT wall-clock time — so
        both entry points share the same timeline and the eviction boundary
        is consistent.

        Call periodically (e.g. on FLOW_CLEANUP_INTERVAL) to prevent
        unbounded memory growth during long captures.
        """
        if self._latest_time == 0.0:
            return  # No flows seen yet

        cutoff = self._latest_time - self.window_seconds
        stale_srcs = []

        for src_ip, entries in self._probe_log.items():
            fresh = [e for e in entries if e[0] >= cutoff]
            if fresh:
                self._probe_log[src_ip] = fresh
            else:
                stale_srcs.append(src_ip)

        for src_ip in stale_srcs:
            del self._probe_log[src_ip]
            # Also clear alerting state if all probes have aged out
            self._alerting.discard(src_ip)
