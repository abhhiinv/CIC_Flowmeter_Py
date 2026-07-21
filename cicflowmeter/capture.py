#!/usr/bin/env python3
"""Live packet capture module using Scapy.

Captures live network traffic and converts packets to PacketInfo objects.
Completely isolated from feature calculation and ML prediction.

Uses a thread-safe queue to pass PacketInfo objects to the flow pipeline
without blocking the capture thread.
"""

import logging
import threading
import time
from queue import Queue, Empty
from typing import Optional, Callable

from scapy.all import sniff, conf

from .pcap_reader import parse_packet
from .packet_info import PacketInfo

logger = logging.getLogger(__name__)

# Sentinel to signal capture is done
CAPTURE_DONE = None


class LiveCapture:
    """Captures live network packets and pushes PacketInfo to a queue.
    
    Runs Scapy sniff() in a dedicated thread to avoid blocking
    the flow processing pipeline.
    
    Thread-safe: the packet queue can be consumed from any thread.
    """
    
    def __init__(self, interface: str,
                 bpf_filter: str = "",
                 packet_count: int = 0,
                 timeout: Optional[float] = None) -> None:
        """
        Args:
            interface: Network interface name (e.g. "Wi-Fi", "Ethernet")
            bpf_filter: Berkeley Packet Filter string (e.g. "tcp port 80")
            packet_count: Max packets to capture (0 = unlimited)
            timeout: Capture timeout in seconds (None = forever)
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count if packet_count > 0 else 0
        self.timeout = timeout
        
        # Thread-safe packet queue
        self.packet_queue: Queue = Queue(maxsize=10000)
        
        # Capture state
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._packets_captured = 0
        self._packets_parsed = 0
        self._running = False
    
    def _packet_callback(self, raw_packet) -> None:
        """Called by Scapy for each captured packet.
        
        Parses the packet into PacketInfo and pushes to queue.
        Non-IP packets are silently dropped.
        """
        self._packets_captured += 1
        
        pkt_info = parse_packet(raw_packet)
        if pkt_info is not None:
            self._packets_parsed += 1
            try:
                self.packet_queue.put_nowait(pkt_info)
            except Exception:
                # Queue full - drop oldest packet to avoid blocking capture
                try:
                    self.packet_queue.get_nowait()
                except Empty:
                    pass
                self.packet_queue.put_nowait(pkt_info)
        
        # Log progress periodically
        if self._packets_captured % 1000 == 0:
            logger.info(f"Captured {self._packets_captured} packets "
                       f"({self._packets_parsed} parsed, "
                       f"queue size: {self.packet_queue.qsize()})")
    
    def _capture_worker(self) -> None:
        """Worker thread that runs Scapy sniff()."""
        try:
            logger.info(f"Starting capture on interface '{self.interface}'")
            if self.bpf_filter:
                logger.info(f"BPF filter: {self.bpf_filter}")
            if self.packet_count:
                logger.info(f"Packet limit: {self.packet_count}")
            if self.timeout:
                logger.info(f"Timeout: {self.timeout}s")
            
            self._running = True
            
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                filter=self.bpf_filter if self.bpf_filter else None,
                count=self.packet_count,
                timeout=self.timeout,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False  # Don't store packets in memory
            )
        except PermissionError:
            logger.error("Permission denied. Run with administrator/root privileges.")
            print("\nERROR: Permission denied.")
            print("Live capture requires administrator/root privileges.")
            print("  Windows: Run Command Prompt as Administrator")
            print("  Linux/Mac: Use 'sudo python main.py ...'")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self._running = False
            # Signal that capture is done
            self.packet_queue.put(CAPTURE_DONE)
            logger.info(f"Capture finished. Total captured: {self._packets_captured}, "
                       f"parsed: {self._packets_parsed}")
    
    def start(self) -> None:
        """Start capturing packets in a background thread."""
        if self._capture_thread and self._capture_thread.is_alive():
            logger.warning("Capture already running")
            return
        
        self._stop_event.clear()
        self._capture_thread = threading.Thread(
            target=self._capture_worker,
            name="packet-capture",
            daemon=True
        )
        self._capture_thread.start()
    
    def stop(self) -> None:
        """Signal the capture to stop."""
        logger.info("Stopping capture...")
        self._stop_event.set()
        if self._capture_thread:
            self._capture_thread.join(timeout=5.0)
    
    def get_packet(self, timeout: float = 1.0) -> Optional[PacketInfo]:
        """Get next parsed packet from the queue.
        
        Returns PacketInfo or None (CAPTURE_DONE sentinel).
        Blocks up to `timeout` seconds if queue is empty.
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except Empty:
            return Empty  # distinguish from CAPTURE_DONE (None)
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    @property
    def stats(self) -> dict:
        return {
            'packets_captured': self._packets_captured,
            'packets_parsed': self._packets_parsed,
            'queue_size': self.packet_queue.qsize(),
            'running': self._running
        }


def list_interfaces() -> None:
    """Print available network interfaces."""
    print("\nAvailable network interfaces:")
    print("-" * 40)
    try:
        # Use Scapy's interface listing
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        for i, iface in enumerate(ifaces, 1):
            name = iface.get('name', 'Unknown')
            desc = iface.get('description', '')
            print(f"  {i}. {name}")
            if desc:
                print(f"     {desc}")
    except ImportError:
        # Non-Windows fallback
        try:
            from scapy.all import get_if_list
            for i, iface in enumerate(get_if_list(), 1):
                print(f"  {i}. {iface}")
        except Exception as e:
            print(f"  Could not list interfaces: {e}")
            print(f"  Try specifying the interface name directly.")
    except Exception as e:
        try:
            from scapy.all import get_if_list
            for i, iface in enumerate(get_if_list(), 1):
                print(f"  {i}. {iface}")
        except Exception:
            print(f"  Could not list interfaces: {e}")
            print(f"  Try specifying the interface name directly.")
