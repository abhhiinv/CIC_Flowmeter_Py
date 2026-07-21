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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('main')


# ======================================================================
# Shared flow completion handler
# ======================================================================

def handle_completed_flow(flow: Flow,
                          csv_writer: Optional[CSVWriter],
                          predictor: Optional[Predictor],
                          flow_num: int) -> None:
    """Process a completed flow: write to CSV and/or run prediction.
    
    This function is called for every flow that finishes (via timeout
    or end of capture). It:
    1. Extracts features
    2. Appends a row to CSV (if csv_writer provided)
    3. Runs ML prediction (if predictor provided)
    4. Prints results to console
    """
    features = flow.get_features()
    
    # Write to CSV
    if csv_writer is not None:
        csv_writer.write_flow(flow)
    
    # Run prediction
    if predictor is not None:
        try:
            result = predictor.predict(features)
            output = Predictor.format_prediction(
                flow.src_ip, flow.src_port,
                flow.dst_ip, flow.dst_port,
                result
            )
            print(f"\n{'-' * 50}")
            print(f"[Flow #{flow_num}]")
            print(output)
            print(f"{'-' * 50}")
            
            # Update the Attack Type in features based on prediction
            features['Attack Type'] = result['label']
        except Exception as e:
            logger.error(f"Prediction error for flow #{flow_num}: {e}")
    else:
        # No prediction - just log flow info
        total_pkts = flow._fwd_count + flow._bwd_count
        print(f"[Flow #{flow_num}] "
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
                 label: str = "Benign") -> None:
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
    print(f"  Flow timeout: {timeout}s")
    print(f"\nPress Ctrl+C to stop capture.\n")
    
    # Initialize components
    manager = FlowManager(timeout=timeout, label="Benign")
    
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
                            flow, csv_writer, predictor_instance, flow_num
                        )
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
                    flow, csv_writer, predictor_instance, flow_num
                )
            
            # Periodic cleanup of timed-out flows
            current_time = time.time()
            if current_time - last_cleanup >= FLOW_CLEANUP_INTERVAL:
                timed_out = manager._check_timeouts(current_time)
                for flow in timed_out:
                    flow_num += 1
                    handle_completed_flow(
                        flow, csv_writer, predictor_instance, flow_num
                    )
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
                handle_completed_flow(flow, csv_writer, predictor_instance, flow_num)
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
    parser.add_argument('--timeout', type=float, default=FLOW_TIMEOUT_SECONDS,
                        help=f'Flow inactivity timeout in seconds '
                             f'(default: {FLOW_TIMEOUT_SECONDS})')
    parser.add_argument('--label', type=str, default='Benign',
                        help='Default attack type label (default: Benign)')
    
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
