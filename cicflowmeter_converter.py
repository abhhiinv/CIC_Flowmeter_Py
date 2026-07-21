#!/usr/bin/env python3
"""
CICFlowMeter Python Clone - PCAP to Flow Feature Converter

Refactored from the original converter.py to produce CICFlowMeter-compatible
feature vectors for machine learning datasets.

Preserves:
  - Multiprocessing (ProcessPoolExecutor)
  - Streaming PCAP reading (PcapReader)
  - Large file chunking
  - Bidirectional flow tracking
  - CSV export
  - Directory processing

Usage:
    python cicflowmeter_converter.py input.pcap output.csv
    python cicflowmeter_converter.py input.pcap output.csv --stream
    python cicflowmeter_converter.py --input-dir ./pcaps --output-dir ./csvs
    python cicflowmeter_converter.py input.pcap output.csv --label "DDoS"
"""

import sys
import os
import tempfile
import argparse
import logging
import multiprocessing
from datetime import datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Optional

import pandas as pd

try:
    from scapy.all import PcapReader, wrpcap
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Please install required packages: pip install scapy pandas")
    sys.exit(1)

from cicflowmeter.packet_info import PacketInfo
from cicflowmeter.flow_key import FlowKey
from cicflowmeter.flow import Flow, COLUMN_NAMES
from cicflowmeter.flow_manager import FlowManager
from cicflowmeter.pcap_reader import parse_packet, read_pcap_streaming, read_pcap_nonstreaming
from cicflowmeter.csv_writer import CSVWriter

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Module-level worker for multiprocessing (must be picklable)
# ──────────────────────────────────────────────────────────────────────

def _process_chunk_worker(chunk_file: str, stream: bool,
                          timeout: float, label: str) -> List[dict]:
    """Worker function for ProcessPoolExecutor.
    
    Processes a single PCAP chunk and returns a list of feature dicts.
    Must be at module level for pickling.
    """
    try:
        manager = FlowManager(timeout=timeout, label=label)
        completed_features: List[dict] = []
        
        # Read packets from chunk
        if stream:
            packet_iter = read_pcap_streaming(chunk_file)
        else:
            packet_iter = read_pcap_nonstreaming(chunk_file)
        
        for pkt in packet_iter:
            timed_out_flows = manager.add_packet(pkt)
            # Collect features from timed-out flows immediately
            for flow in timed_out_flows:
                completed_features.append(flow.get_features())
        
        # Flush remaining active flows
        remaining = manager.flush_all()
        for flow in remaining:
            completed_features.append(flow.get_features())
        
        return completed_features
    except Exception as e:
        print(f"Worker error for {chunk_file}: {e}")
        return []


# ──────────────────────────────────────────────────────────────────────
# Main Converter Class
# ──────────────────────────────────────────────────────────────────────

class CICFlowMeterConverter:
    """Converts PCAP files to CICFlowMeter-compatible CSV feature files.
    
    Preserves the original converter's architecture:
    - Multiprocessing for large files
    - Streaming for memory efficiency
    - Chunking for multi-GB PCAPs
    - Directory batch processing
    """
    
    def __init__(self, chunk_size_mb: int = 1024,
                 flow_timeout: float = 120.0,
                 max_workers: int = None,
                 label: str = "Benign") -> None:
        self.chunk_size_mb = chunk_size_mb
        self.flow_timeout = flow_timeout
        self.max_workers = max_workers or min(multiprocessing.cpu_count(), 4)
        self.label = label
    
    # ── File Discovery ────────────────────────────────────────────
    
    def find_pcap_files(self, directory: str) -> List[Path]:
        """Find all PCAP files in a directory."""
        pcap_files = []
        directory = Path(directory)
        
        pcap_extensions = ['*.pcap', '*.pcapng', '*.cap', '*.dmp']
        for ext in pcap_extensions:
            pcap_files.extend(directory.glob(ext))
            pcap_files.extend(directory.glob(ext.upper()))
        
        pcap_files = sorted(list(set(pcap_files)))
        
        print(f"Found {len(pcap_files)} PCAP files in {directory}")
        for pf in pcap_files:
            size_mb = pf.stat().st_size / (1024 * 1024)
            print(f"  - {pf.name} ({size_mb:.1f} MB)")
        
        return pcap_files
    
    # ── Chunking ──────────────────────────────────────────────────
    
    def _get_file_size_mb(self, file_path: str) -> float:
        """Get file size in MB."""
        return os.path.getsize(file_path) / (1024 * 1024)
    
    def _split_pcap_streaming(self, pcap_file: str) -> List[str]:
        """Split large PCAP files into smaller chunks using streaming.
        
        Preserves the original chunking approach from converter.py.
        """
        file_size_mb = self._get_file_size_mb(pcap_file)
        
        if file_size_mb <= self.chunk_size_mb:
            return [pcap_file]
        
        print(f"Large PCAP detected ({file_size_mb:.1f} MB). "
              f"Splitting into {self.chunk_size_mb}MB chunks...")
        
        chunk_files = []
        temp_dir = tempfile.mkdtemp()
        current_chunk = []
        current_chunk_size = 0
        chunk_num = 1
        target_bytes = self.chunk_size_mb * 1024 * 1024
        
        try:
            with PcapReader(pcap_file) as reader:
                for packet in reader:
                    packet_size = len(packet)
                    current_chunk.append(packet)
                    current_chunk_size += packet_size
                    
                    if current_chunk_size >= target_bytes:
                        chunk_path = os.path.join(temp_dir, f"chunk_{chunk_num}.pcap")
                        wrpcap(chunk_path, current_chunk)
                        chunk_files.append(chunk_path)
                        current_chunk = []
                        current_chunk_size = 0
                        chunk_num += 1
                
                if current_chunk:
                    chunk_path = os.path.join(temp_dir, f"chunk_{chunk_num}.pcap")
                    wrpcap(chunk_path, current_chunk)
                    chunk_files.append(chunk_path)
        except Exception as e:
            # Cleanup on error
            for cf in chunk_files:
                try:
                    os.remove(cf)
                except OSError:
                    pass
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass
            raise RuntimeError(f"Error during PCAP splitting: {e}") from e
        
        print(f"  Split into {len(chunk_files)} chunks")
        return chunk_files
    
    def _cleanup_chunks(self, chunk_files: List[str], pcap_file: str) -> None:
        """Clean up temporary chunk files."""
        for cf in chunk_files:
            if cf != pcap_file:
                try:
                    os.remove(cf)
                except OSError:
                    pass
        if chunk_files and chunk_files[0] != pcap_file:
            try:
                os.rmdir(os.path.dirname(chunk_files[0]))
            except OSError:
                pass
    
    # ── Core Conversion ───────────────────────────────────────────
    
    def convert_pcap(self, pcap_file: str, output_file: str,
                     stream: bool = True,
                     suppress_output: bool = False) -> int:
        """Convert a single PCAP file to CICFlowMeter CSV.
        
        Returns the number of flows written.
        """
        start_time = datetime.now()
        
        # Check if chunking is needed
        chunk_files = self._split_pcap_streaming(pcap_file)
        is_chunked = len(chunk_files) > 1
        
        all_features: List[dict] = []
        
        if is_chunked and self.max_workers > 1:
            # ── Parallel processing ──
            if not suppress_output:
                print(f"Running parallel processing with {self.max_workers} workers...")
            all_features = self._process_parallel(chunk_files, stream)
        else:
            # ── Sequential processing ──
            if not suppress_output:
                print("Running sequential flow conversion...")
            all_features = self._process_sequential(
                chunk_files, stream, suppress_output, is_chunked
            )
        
        # Cleanup temp chunks
        if is_chunked:
            self._cleanup_chunks(chunk_files, pcap_file)
        
        if not suppress_output:
            print(f"\n*) Total flows identified: {len(all_features)}")
        
        # Write CSV
        self._write_features_to_csv(all_features, output_file)
        
        if not suppress_output:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"-> Flow analysis saved to: {output_file}")
            print(f"-> Processing time: {elapsed:.2f} seconds")
            self._display_summary(all_features)
        
        return len(all_features)
    
    def _process_sequential(self, chunk_files: List[str], stream: bool,
                            suppress_output: bool, is_chunked: bool) -> List[dict]:
        """Process chunks sequentially."""
        all_features: List[dict] = []
        
        for i, chunk_file in enumerate(chunk_files, 1):
            if is_chunked and not suppress_output:
                print(f"\nProcessing chunk {i}/{len(chunk_files)}...")
            
            manager = FlowManager(timeout=self.flow_timeout, label=self.label)
            packet_count = 0
            
            if stream:
                packet_iter = read_pcap_streaming(chunk_file)
            else:
                packet_iter = read_pcap_nonstreaming(chunk_file)
            
            for pkt in packet_iter:
                packet_count += 1
                if not suppress_output and packet_count % 10000 == 0:
                    stats = manager.get_stats()
                    print(f"  Processed {packet_count} packets, "
                          f"{stats['active_flows']} active flows")
                
                timed_out = manager.add_packet(pkt)
                for flow in timed_out:
                    all_features.append(flow.get_features())
            
            # Flush remaining
            remaining = manager.flush_all()
            for flow in remaining:
                all_features.append(flow.get_features())
            
            if not suppress_output:
                print(f"  Chunk {i}: {packet_count} packets -> "
                      f"{len(all_features)} total flows")
        
        return all_features
    
    def _process_parallel(self, chunk_files: List[str],
                          stream: bool) -> List[dict]:
        """Process chunks in parallel using ProcessPoolExecutor."""
        all_features: List[dict] = []
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            print(f"Submitting {len(chunk_files)} chunks to "
                  f"{self.max_workers} workers...")
            
            future_to_chunk = {}
            for chunk_file in chunk_files:
                future = executor.submit(
                    _process_chunk_worker, chunk_file, stream,
                    self.flow_timeout, self.label
                )
                future_to_chunk[future] = chunk_file
            
            completed = 0
            for future in as_completed(future_to_chunk):
                chunk_file = future_to_chunk[future]
                chunk_name = os.path.basename(chunk_file)
                try:
                    chunk_features = future.result()
                    all_features.extend(chunk_features)
                    completed += 1
                    print(f"Completed {completed}/{len(chunk_files)} - "
                          f"{chunk_name}: {len(chunk_features)} flows")
                except Exception as e:
                    print(f"Error processing chunk {chunk_name}: {e}")
        
        return all_features
    
    def _write_features_to_csv(self, features: List[dict],
                               output_file: str) -> None:
        """Write feature dicts to CSV using pandas with exact column order."""
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        if not features:
            # Write empty CSV with headers
            df = pd.DataFrame(columns=COLUMN_NAMES)
        else:
            df = pd.DataFrame(features)
            # Ensure exact column order
            df = df[COLUMN_NAMES]
        
        # Replace NaN/None with 0
        df = df.fillna(0)
        # Replace inf with 0
        df = df.replace([float('inf'), float('-inf')], 0)
        
        df.to_csv(output_file, index=False)
    
    # ── Directory Processing ──────────────────────────────────────
    
    def process_directory_separate(self, input_dir: str, output_dir: str,
                                   stream: bool = True) -> None:
        """Process each PCAP file in a directory separately."""
        pcap_files = self.find_pcap_files(input_dir)
        if not pcap_files:
            print(f"No PCAP files found in {input_dir}")
            return
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        successful = 0
        failed = []
        
        print(f"\nProcessing {len(pcap_files)} PCAP files separately...")
        
        for i, pf in enumerate(pcap_files, 1):
            try:
                print(f"\n[{i}/{len(pcap_files)}] Processing {pf.name}...")
                output_file = output_path / f"{pf.stem}_flows.csv"
                
                self.convert_pcap(
                    str(pf), str(output_file),
                    stream=stream, suppress_output=True
                )
                successful += 1
                print(f"  -> Saved to {output_file}")
            except Exception as e:
                print(f"  -> ERROR: {pf.name}: {e}")
                failed.append(pf.name)
        
        print(f"\n{'='*50}")
        print(f"Batch Processing Summary:")
        print(f"  Successful: {successful}/{len(pcap_files)}")
        print(f"  Failed: {len(failed)}")
        if failed:
            print(f"  Failed files: {', '.join(failed)}")
    
    def process_directory_merged(self, input_dir: str, output_dir: str,
                                  stream: bool = True) -> None:
        """Process all PCAP files in a directory and merge into single CSV."""
        pcap_files = self.find_pcap_files(input_dir)
        if not pcap_files:
            print(f"No PCAP files found in {input_dir}")
            return
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_path / f"merged_flows_{timestamp}.csv"
        
        all_features: List[dict] = []
        successful = 0
        failed = []
        
        print(f"\nProcessing {len(pcap_files)} PCAP files for merging...")
        
        for i, pf in enumerate(pcap_files, 1):
            try:
                print(f"\n[{i}/{len(pcap_files)}] Analyzing {pf.name}...")
                
                # Process this file
                manager = FlowManager(timeout=self.flow_timeout, label=self.label)
                if stream:
                    packet_iter = read_pcap_streaming(str(pf))
                else:
                    packet_iter = read_pcap_nonstreaming(str(pf))
                
                file_features: List[dict] = []
                for pkt in packet_iter:
                    timed_out = manager.add_packet(pkt)
                    for flow in timed_out:
                        file_features.append(flow.get_features())
                
                remaining = manager.flush_all()
                for flow in remaining:
                    file_features.append(flow.get_features())
                
                all_features.extend(file_features)
                successful += 1
                print(f"  -> Found {len(file_features)} flows")
            except Exception as e:
                print(f"  -> ERROR: {pf.name}: {e}")
                failed.append(pf.name)
        
        # Write merged CSV
        self._write_features_to_csv(all_features, str(output_file))
        
        print(f"\n{'='*50}")
        print(f"Merged Processing Summary:")
        print(f"  Files processed: {successful}/{len(pcap_files)}")
        print(f"  Total flows: {len(all_features)}")
        print(f"  Output: {output_file}")
        if failed:
            print(f"  Failed: {', '.join(failed)}")
    
    # ── Display ───────────────────────────────────────────────────
    
    def _display_summary(self, features: List[dict]) -> None:
        """Display summary statistics."""
        if not features:
            print("No flows to summarize.")
            return
        
        df = pd.DataFrame(features)
        
        print(f"\n{'='*20} Flow Analysis Summary {'='*20}")
        print(f"*) Total flows: {len(df)}")
        
        # Duration stats
        durations_s = df['Flow Duration'] / 1_000_000  # us to s
        print(f"\n*) Flow duration statistics:")
        print(f"  Average: {durations_s.mean():.2f} seconds")
        print(f"  Median:  {durations_s.median():.2f} seconds")
        print(f"  Max:     {durations_s.max():.2f} seconds")
        
        # Packet stats
        total_pkts = df['Total Fwd Packets'] + df.get('Total Bwd Packets', 0)
        if 'Total Fwd Packets' in df.columns:
            print(f"\n*) Packet statistics:")
            print(f"  Avg fwd packets/flow: {df['Total Fwd Packets'].mean():.1f}")
        
        # Feature count verification
        print(f"\n*) Features per flow: {len(COLUMN_NAMES)}")
        print(f"*) Columns: {', '.join(COLUMN_NAMES[:5])}... ({len(COLUMN_NAMES)} total)")
    
    def quick_preview(self, pcap_file: str, num_flows: int = 5,
                      stream: bool = True) -> None:
        """Display a quick preview of flows from a PCAP file."""
        manager = FlowManager(timeout=self.flow_timeout, label=self.label)
        
        if stream:
            packet_iter = read_pcap_streaming(pcap_file)
        else:
            packet_iter = read_pcap_nonstreaming(pcap_file)
        
        all_features: List[dict] = []
        for pkt in packet_iter:
            timed_out = manager.add_packet(pkt)
            for flow in timed_out:
                all_features.append(flow.get_features())
        
        remaining = manager.flush_all()
        for flow in remaining:
            all_features.append(flow.get_features())
        
        print(f"\n=== Flow Preview (First {min(num_flows, len(all_features))} of {len(all_features)} flows) ===")
        print(f"{'#':<3} {'Dst Port':<10} {'Duration(us)':<15} {'Fwd Pkts':<10} {'Fwd Bytes':<12} {'Bwd Pkts':<10}")
        print("-" * 70)
        
        for i, feat in enumerate(all_features[:num_flows], 1):
            print(f"{i:<3} {feat['Destination Port']:<10} "
                  f"{feat['Flow Duration']:<15} "
                  f"{feat['Total Fwd Packets']:<10} "
                  f"{feat['Total Length of Fwd Packets']:<12}")
        print("-" * 70)


# ──────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='CICFlowMeter Python Clone - PCAP to Flow Feature Converter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cicflowmeter_converter.py input.pcap output.csv
  python cicflowmeter_converter.py input.pcap output.csv --stream
  python cicflowmeter_converter.py --input-dir ./pcaps --output-dir ./csvs
  python cicflowmeter_converter.py input.pcap output.csv --label "DDoS"
        """
    )
    
    # Positional arguments (for single file mode)
    parser.add_argument('input_file', nargs='?', help='Input PCAP file')
    parser.add_argument('output_file', nargs='?', help='Output CSV file')
    
    # Directory mode
    parser.add_argument('--input-dir', help='Input directory containing PCAP files')
    parser.add_argument('--output-dir', help='Output directory for CSV files')
    parser.add_argument('--merge', action='store_true',
                        help='Merge all PCAP files into single CSV (directory mode)')
    
    # Processing options
    parser.add_argument('--stream', action='store_true', default=True,
                        help='Use streaming mode (default: True)')
    parser.add_argument('--no-stream', action='store_true',
                        help='Disable streaming (load entire PCAP into memory)')
    parser.add_argument('--timeout', type=float, default=120.0,
                        help='Flow inactivity timeout in seconds (default: 120)')
    parser.add_argument('--chunk-size', type=int, default=1024,
                        help='Chunk size in MB for large files (default: 1024)')
    parser.add_argument('--workers', type=int, default=None,
                        help='Number of parallel workers (default: auto)')
    parser.add_argument('--label', type=str, default='Benign',
                        help='Attack type label (default: Benign)')
    
    # Preview
    parser.add_argument('--quick-preview', type=int, default=0,
                        help='Show preview of N flows before full conversion')
    
    args = parser.parse_args()
    
    # Determine streaming mode
    use_stream = not args.no_stream
    
    # Create converter
    converter = CICFlowMeterConverter(
        chunk_size_mb=args.chunk_size,
        flow_timeout=args.timeout,
        max_workers=args.workers,
        label=args.label
    )
    
    # Directory mode
    if args.input_dir:
        if not args.output_dir:
            args.output_dir = args.input_dir + '_flows'
        
        if args.merge:
            converter.process_directory_merged(
                args.input_dir, args.output_dir, stream=use_stream
            )
        else:
            converter.process_directory_separate(
                args.input_dir, args.output_dir, stream=use_stream
            )
        return
    
    # Single file mode
    if not args.input_file:
        parser.error('Either input_file or --input-dir is required')
    
    if not args.output_file:
        # Default output filename
        input_path = Path(args.input_file)
        args.output_file = str(input_path.parent / f"{input_path.stem}_flows.csv")
    
    # Quick preview
    if args.quick_preview > 0:
        converter.quick_preview(args.input_file, args.quick_preview, use_stream)
        response = input("\nContinue with full conversion? (y/n): ").lower().strip()
        if response != 'y':
            print("Conversion cancelled.")
            return
    
    # Convert
    converter.convert_pcap(
        args.input_file, args.output_file, stream=use_stream
    )


if __name__ == '__main__':
    main()
