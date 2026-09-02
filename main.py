#!/usr/bin/env python3
"""CICFlowMeter Clone - Real-Time Intrusion Detection Pipeline

Unified CLI entry point supporting:
  1. Offline PCAP-to-CSV conversion
  2. Live packet capture with flow assembly
  3. Real-time ML prediction on completed flows

Usage:
  python main.py --pcap sample.pcap --output output.csv
  python main.py --pcap sample.pcap --output output.csv --predict
  python main.py --live --interface Wi-Fi
  python main.py --live --interface Wi-Fi --predict
  python main.py --live --interface Wi-Fi --output live.csv --predict
  python main.py --live --interface Ethernet --filter "tcp port 80"
  python main.py --list-interfaces
"""

import sys
import os
import argparse
import logging
import threading
import time
from queue import Empty
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cicflowmeter.packet_info import PacketInfo
from cicflowmeter.flow import Flow, COLUMN_NAMES
from cicflowmeter.flow_manager import FlowManager
from cicflowmeter.pcap_reader import read_pcap_streaming, read_pcap_nonstreaming
from cicflowmeter.csv_writer import CSVWriter
from cicflowmeter.config import (
    FLOW_TIMEOUT_SECONDS, FLOW_CLEANUP_INTERVAL,
    MODEL_FEATURE_COLUMNS
)
from cicflowmeter.capture import LiveCapture, CAPTURE_DONE, list_interfaces
from cicflowmeter.predictor import Predictor
from cicflowmeter.portscan_detector import PortScanDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('main')


# ======================================================================
# Shared flow completion handler
# ======================================================================

def is_internal_traffic(src_ip: str, dst_ip: str) -> bool:
    """Return True if this flow is local/infrastructure traffic that should be
    skipped during ML prediction.

    These addresses are never present in CIC-IDS2017 training data, so the
    model will always produce meaningless (often falsely alarming) predictions
    for them.

    Filtered prefixes / addresses:
      - IPv6 link-local source     fe80:: (covers all practical link-local assignments)
      - IPv6 multicast destination ff00::/8  (ff prefix)
      - IPv6 loopback              ::1
      - IPv4 loopback              127.0.0.0/8
      - IPv4 broadcast             255.255.255.255
      - IPv4 link-local            169.254.0.0/16
      - IPv4 multicast             224.0.0.0/4  (first octet 224-239)
    """
    src = src_ip.lower()
    dst = dst_ip.lower()

    # IPv6 link-local source (fe80::...)
    # Note: fe80::/10 technically covers fe80-febf, but all real OS assignments
    # use fe80:: so this prefix check is sufficient in practice.
    if src.startswith("fe80:"):
        return True
    # IPv6 multicast destination (ff01::..., ff02::..., ff0e::..., etc.)
    if dst.startswith("ff"):
        return True
    # IPv6 loopback
    if src in ("::1", "0:0:0:0:0:0:0:1") or dst in ("::1", "0:0:0:0:0:0:0:1"):
        return True
    # IPv4 loopback
    if src.startswith("127.") or dst.startswith("127."):
        return True
    # IPv4 broadcast
    if dst == "255.255.255.255":
        return True
    # IPv4 link-local (APIPA)
    if src.startswith("169.254.") or dst.startswith("169.254."):
        return True
    # IPv4 multicast: 224.0.0.0/4 = first octet 224-239.
    # Using integer comparison instead of startswith() to correctly cover
    # the full range (224-239), including 228-238 which were previously missed.
    dst_parts = dst.split(".")
    if len(dst_parts) == 4:
        try:
            if 224 <= int(dst_parts[0]) <= 239:
                return True
        except ValueError:
            pass

    return False


def handle_completed_flow(flow: Flow,
                          csv_writer: Optional[CSVWriter],
                          predictor: Optional[Predictor],
                          flow_num: int,
                          portscan_detector: Optional[PortScanDetector] = None) -> None:
    """Process a completed flow: write to CSV and/or run prediction.
    
    This function is called for every flow that finishes (via timeout
    or end of capture). It:
    1. Extracts features
    2. Appends a row to CSV (if csv_writer provided)
    3. Runs ML prediction (if predictor provided)
    4. Overrides prediction with "Port Scan" if cross-flow detector fires
    5. Prints results to console
    """
    features = flow.get_features()
    
    
    # Get readable timestamp from flow start time
    start_dt = datetime.fromtimestamp(flow.start_time).strftime('%Y-%m-%d %H:%M:%S')

    # --- Cross-flow port scan detector (runs on ALL flows, before any filter) ---
    # Must run before is_internal_traffic() so that fe80::→fe80:: unicast
    # link-local port scans are counted and alerted on even though the ML
    # model never sees link-local traffic.
    scan_result = None
    if portscan_detector is not None:
        is_scan, is_new_episode, unique_ports = portscan_detector.record_and_check(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            flow_end_time=flow.end_time
        )
        if is_scan:
            scan_result = {
                'label': 'Port Scan',
                'confidence': None,
                'probabilities': None,
                '_scan_unique_ports': unique_ports,
                '_scan_new_episode': is_new_episode
            }

    # If a new port scan episode just fired, print the alert regardless of
    # whether this is internal traffic — IPv6 link-local scans are real attacks.
    if scan_result is not None and scan_result.get('_scan_new_episode'):
        output = Predictor.format_prediction(
            flow.src_ip, flow.src_port,
            flow.dst_ip, flow.dst_port,
            scan_result
        )
        output += (f"\n  [Port Scan Detector] {scan_result['_scan_unique_ports']} unique "
                   f"ports contacted by {flow.src_ip} in scan window")
        print(f"\n{'-' * 50}")
        print(f"[Flow #{flow_num}] Captured at {start_dt}")
        print(output)
        print(f"{'-' * 50}")

    # Skip internal/infrastructure traffic from ML prediction and normal output.
    # Write to CSV first with final label, then return early.
    if is_internal_traffic(flow.src_ip, flow.dst_ip):
        if scan_result is None or not scan_result.get('_scan_new_episode'):
            logger.debug(f"Flow #{flow_num}: suppressing internal traffic "
                         f"({flow.src_ip} -> {flow.dst_ip})")
        if csv_writer is not None:
            if scan_result is not None:
                flow.label = scan_result['label']
            csv_writer.write_flow(flow)
        return

    # Run ML prediction
    if predictor is not None:
        try:
            # Use the scan override result if detector already fired above,
            # otherwise get a fresh ML prediction.
            if scan_result is not None:
                result = scan_result
            else:
                result = predictor.predict(features)

            # Only print the full alert block on the first flow of a new scan
            # episode. Ongoing-episode flows are logged at DEBUG level.
            # (New-episode case already printed above before the internal filter.)
            if result.get('_scan_new_episode'):
                # Already printed above — just update Attack Type
                pass
            elif result.get('label') == 'Port Scan':
                # Ongoing episode — log quietly so terminal isn't spammed
                logger.debug(
                    f"Flow #{flow_num} ({flow.src_ip}:{flow.src_port} -> "
                    f"{flow.dst_ip}:{flow.dst_port}) labelled Port Scan "
                    f"(episode ongoing, {result.get('_scan_unique_ports')} unique ports)"
                )
            else:
                output = Predictor.format_prediction(
                    flow.src_ip, flow.src_port,
                    flow.dst_ip, flow.dst_port,
                    result
                )
                print(f"\n{'-' * 50}")
                print(f"[Flow #{flow_num}] Captured at {start_dt}")
                print(output)
                print(f"{'-' * 50}")

            # Update the Attack Type in features based on prediction
            features['Attack Type'] = result['label']
            flow.label = result['label']
            if csv_writer is not None:
                csv_writer.write_flow(flow)
        except Exception as e:
            logger.error(f"Prediction error for flow #{flow_num}: {e}")
    else:
        # No prediction - just log flow info
        if csv_writer is not None:
            csv_writer.write_flow(flow)
        total_pkts = flow._fwd_count + flow._bwd_count
        print(f"[Flow #{flow_num}] {start_dt} | "
              f"{flow.src_ip}:{flow.src_port} -> "
              f"{flow.dst_ip}:{flow.dst_port} | "
              f"{total_pkts} pkts | "
              f"Duration: {features['Flow Duration']} us")



# ======================================================================
# Offline PCAP processing
# ======================================================================

def process_pcap(pcap_file: str, output_file: str,
                 predict: bool = False,
                 timeout: float = FLOW_TIMEOUT_SECONDS,
                 label: str = "Normal Traffic") -> None:
    """Process a PCAP file: extract features, write CSV, optionally predict."""
    print(f"\nProcessing PCAP: {pcap_file}")
    print(f"Output CSV: {output_file}")
    if predict:
        print("ML Prediction: ENABLED")
    
    start_time = datetime.now()
    
    # Initialize components
    manager = FlowManager(timeout=timeout, label=label)
    csv_writer = CSVWriter(output_file, mode="streaming")
    csv_writer.open()
    
    predictor_instance = None
    if predict:
        predictor_instance = Predictor()
        print("Loading ML model...")
        predictor_instance.load()
        print("Model loaded.")
    
    flow_num = 0
    packet_count = 0
    
    # Stream through the PCAP
    for pkt in read_pcap_streaming(pcap_file):
        packet_count += 1
        
        if packet_count % 10000 == 0:
            stats = manager.get_stats()
            print(f"  Processed {packet_count} packets, "
                  f"{stats['active_flows']} active flows, "
                  f"{flow_num} completed flows")
        
        # Add packet and handle any timed-out flows
        timed_out_flows = manager.add_packet(pkt)
        for flow in timed_out_flows:
            flow_num += 1
            handle_completed_flow(flow, csv_writer, predictor_instance, flow_num)
    
    # Flush all remaining active flows
    remaining = manager.flush_all()
    for flow in remaining:
        flow_num += 1
        handle_completed_flow(flow, csv_writer, predictor_instance, flow_num)
    
    csv_writer.close()
    
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n{'=' * 50}")
    print(f"PCAP Processing Complete")
    print(f"  Packets processed: {packet_count}")
    print(f"  Flows identified: {flow_num}")
    print(f"  Output CSV: {output_file}")
    print(f"  Processing time: {elapsed:.2f}s")
    print(f"{'=' * 50}")


# ======================================================================
# Live capture mode
# ======================================================================

def process_live(interface: str,
                 output_file: Optional[str] = None,
                 predict: bool = False,
                 psd: bool = False,
                 bpf_filter: str = "",
                 packet_count: int = 0,
                 capture_timeout: Optional[float] = None,
                 timeout: float = FLOW_TIMEOUT_SECONDS) -> None:
    """Run live packet capture with real-time flow analysis and prediction.
    
    Architecture:
    - Capture thread: Scapy sniff() -> packet queue
    - Main thread: dequeue packets -> flow manager -> CSV + prediction
    - Cleanup timer: periodic timeout sweep of idle flows
    
    This design avoids blocking packet capture during feature extraction
    or ML prediction.
    """
    print(f"\nLive Capture Mode")
    print(f"  Interface: {interface}")
    if bpf_filter:
        print(f"  BPF Filter: {bpf_filter}")
    if output_file:
        print(f"  Output CSV: {output_file}")
    if predict:
        print(f"  ML Prediction: ENABLED")
    if psd:
        print(f"  Port Scan Detector: ENABLED")
    print(f"  Flow timeout: {timeout}s")
    print(f"\nPress Ctrl+C to stop capture.\n")
    
    # Initialize components
    manager = FlowManager(timeout=timeout, label="Normal Traffic")
    
    csv_writer = None
    if output_file:
        csv_writer = CSVWriter(output_file, mode="streaming")
        csv_writer.open()
    
    predictor_instance = None
    if predict:
        predictor_instance = Predictor()
        print("Loading ML model...")
        predictor_instance.load()
        print("Model loaded. Starting capture...\n")

    portscan_detector = None
    if psd:
        portscan_detector = PortScanDetector()
        print(f"Port Scan Detector active "
              f"(threshold: {portscan_detector.port_threshold} unique ports "
              f"/ {portscan_detector.window_seconds:.0f}s window)\n")
    
    # Start live capture
    capture = LiveCapture(
        interface=interface,
        bpf_filter=bpf_filter,
        packet_count=packet_count,
        timeout=capture_timeout
    )
    capture.start()
    
    flow_num = 0
    total_packets = 0
    last_cleanup = time.time()
    
    try:
        while True:
            # Get packet from capture queue
            pkt = capture.get_packet(timeout=1.0)
            
            # Check for sentinel values
            if pkt is CAPTURE_DONE:
                logger.info("Capture finished (done sentinel received)")
                break
            
            if pkt is Empty:
                # Timeout - no packet available. Still do cleanup.
                current_time = time.time()
                if current_time - last_cleanup >= FLOW_CLEANUP_INTERVAL:
                    timed_out = manager._check_timeouts(current_time)
                    for flow in timed_out:
                        flow_num += 1
                        handle_completed_flow(
                            flow, csv_writer, predictor_instance, flow_num,
                            portscan_detector
                        )
                    if portscan_detector is not None:
                        portscan_detector.evict_stale()
                    last_cleanup = current_time
                continue
            
            # Got a valid PacketInfo
            total_packets += 1
            
            if total_packets % 1000 == 0:
                stats = manager.get_stats()
                cap_stats = capture.stats
                print(f"  [{total_packets} packets] "
                      f"Active flows: {stats['active_flows']}, "
                      f"Completed: {flow_num}, "
                      f"Queue: {cap_stats['queue_size']}")
            
            # Add to flow manager
            timed_out_flows = manager.add_packet(pkt)
            for flow in timed_out_flows:
                flow_num += 1
                handle_completed_flow(
                    flow, csv_writer, predictor_instance, flow_num,
                    portscan_detector
                )
            
            # Periodic cleanup of timed-out flows
            current_time = time.time()
            if current_time - last_cleanup >= FLOW_CLEANUP_INTERVAL:
                timed_out = manager._check_timeouts(current_time)
                for flow in timed_out:
                    flow_num += 1
                    handle_completed_flow(
                        flow, csv_writer, predictor_instance, flow_num,
                        portscan_detector
                    )
                if portscan_detector is not None:
                    portscan_detector.evict_stale()
                last_cleanup = current_time
    
    except KeyboardInterrupt:
        print("\n\nCapture interrupted by user.")
    finally:
        # Stop capture
        capture.stop()
        
        # Flush all remaining flows
        print("\nFlushing remaining active flows...")
        remaining = manager.flush_all()
        for flow in remaining:
            flow_num += 1
            try:
                handle_completed_flow(flow, csv_writer, predictor_instance, flow_num,
                                      portscan_detector)
            except KeyboardInterrupt:
                print("\nFlush interrupted.")
                break
        # Close CSV
        if csv_writer is not None:
            csv_writer.close()
        
        # Summary
        print(f"\n{'=' * 50}")
        print(f"Live Capture Summary")
        cap_stats = capture.stats
        print(f"  Packets captured: {cap_stats['packets_captured']}")
        print(f"  Packets parsed (IP): {cap_stats['packets_parsed']}")
        print(f"  Flows completed: {flow_num}")
        if output_file:
            print(f"  Output CSV: {output_file}")
        print(f"{'=' * 50}")


# ======================================================================
# CLI
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description='CICFlowMeter Clone - Real-Time Intrusion Detection Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --pcap sample.pcap --output output.csv
  %(prog)s --pcap sample.pcap --output output.csv --predict
  %(prog)s --live --interface Wi-Fi
  %(prog)s --live --interface Wi-Fi --predict
  %(prog)s --live --interface Wi-Fi --predict --psd
  %(prog)s --live --interface Wi-Fi --psd
  %(prog)s --live --interface Wi-Fi --output live.csv --predict
  %(prog)s --live --interface Ethernet --filter "tcp port 80"
  %(prog)s --list-interfaces
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--pcap', type=str, metavar='FILE',
                            help='Offline mode: process a PCAP file')
    mode_group.add_argument('--live', action='store_true',
                            help='Live mode: capture from network interface')
    mode_group.add_argument('--list-interfaces', action='store_true',
                            help='List available network interfaces')
    
    # Common options
    parser.add_argument('--output', '-o', type=str, metavar='FILE',
                        help='Output CSV file path')
    parser.add_argument('--predict', action='store_true',
                        help='Enable ML prediction on completed flows')
    parser.add_argument('--psd', action='store_true',
                        help='Enable cross-flow Port Scan Detector (works with or without --predict)')
    parser.add_argument('--timeout', type=float, default=FLOW_TIMEOUT_SECONDS,
                        help=f'Flow inactivity timeout in seconds '
                             f'(default: {FLOW_TIMEOUT_SECONDS}; '
                             f'lower values emit long-lived TCP flows sooner)')
    parser.add_argument('--label', type=str, default='Normal Traffic',
                        help='Default attack type label (default: Normal Traffic)')
    
    # Live capture options
    live_group = parser.add_argument_group('Live capture options')
    live_group.add_argument('--interface', '-i', type=str,
                            help='Network interface name (e.g. Wi-Fi, Ethernet)')
    live_group.add_argument('--filter', type=str, default='',
                            help='BPF filter string (e.g. "tcp port 80")')
    live_group.add_argument('--count', type=int, default=0,
                            help='Max packets to capture (0 = unlimited)')
    live_group.add_argument('--capture-timeout', type=float, default=None,
                            help='Capture timeout in seconds')
    
    # Logging
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # ── List interfaces ──
    if args.list_interfaces:
        list_interfaces()
        return
    
    # ── Live mode ──
    if args.live:
        if not args.interface:
            parser.error('--interface is required for live capture mode')
        
        process_live(
            interface=args.interface,
            output_file=args.output,
            predict=args.predict,
            psd=args.psd,
            bpf_filter=args.filter,
            packet_count=args.count,
            capture_timeout=args.capture_timeout,
            timeout=args.timeout
        )
        return
    
    # ── Offline PCAP mode ──
    if args.pcap:
        if not os.path.exists(args.pcap):
            parser.error(f'PCAP file not found: {args.pcap}')
        
        if not args.output:
            # Default output path: same directory, _flows.csv suffix
            pcap_path = Path(args.pcap)
            args.output = str(pcap_path.parent / f"{pcap_path.stem}_flows.csv")
        
        process_pcap(
            pcap_file=args.pcap,
            output_file=args.output,
            predict=args.predict,
            timeout=args.timeout,
            label=args.label
        )
        return
    
    # No mode selected
    parser.print_help()
    print("\nError: Specify --pcap, --live, or --list-interfaces")
    sys.exit(1)


if __name__ == '__main__':
    main()
