#!/usr/bin/env python3
"""CSVWriter - writes flow features to CSV with exact column ordering.

Supports:
  - Streaming writes (append rows as flows complete)
  - Batch writes using pandas
  - Exact column ordering matching CICFlowMeter output
  - No NaN, None, or empty values (replaced with 0)
"""

import csv
import os
import logging
from typing import List, Dict, Any, Optional

import pandas as pd

from .flow import COLUMN_NAMES, Flow

logger = logging.getLogger(__name__)


class CSVWriter:
    """Writes flow features to CSV files.
    
    Two modes:
    1. Streaming: open file, write header, append rows as flows complete
    2. Batch: collect all flow dicts and write at once using pandas
    """
    
    def __init__(self, output_path: str, mode: str = "streaming" , flush_every=1) -> None:
        self.output_path = output_path
        self.mode = mode
        self._file = None
        self._writer = None
        self._row_count = 0
        self._header_written = False
        self._flush_every = flush_every
        # For batch mode
        self._batch_rows: List[Dict[str, Any]] = []
    
    def open(self) -> None:
        """Open the CSV file for streaming writes."""
        if self.mode == "streaming":
            # Ensure parent directory exists
            os.makedirs(os.path.dirname(os.path.abspath(self.output_path)), exist_ok=True)
            self._file = open(self.output_path, 'w', newline='', encoding='utf-8')
            self._writer = csv.writer(self._file)
            self._writer.writerow(COLUMN_NAMES)
            self._header_written = True
    
    def write_flow(self, flow: Flow) -> None:
        """Write a single flow's features to CSV.
        
        In streaming mode, writes immediately to disk.
        In batch mode, collects for later bulk write.
        """
        features = flow.get_features()
        
        if self.mode == "streaming":
            if self._writer is None:
                self.open()
            row = [features.get(col, 0) for col in COLUMN_NAMES]
            # Sanitize: replace None/NaN with 0
            row = [0 if (v is None or (isinstance(v, float) and v != v)) else v
                   for v in row]
            self._writer.writerow(row)
            self._row_count += 1
            
            # Periodic flush for large files
            if self._row_count % self._flush_every == 0:
                self._file.flush()
        else:
            # Batch mode: collect for later
            self._batch_rows.append(features)
    
    def write_flows(self, flows: List[Flow]) -> None:
        """Write multiple flows."""
        for flow in flows:
            self.write_flow(flow)
    
    def close(self) -> None:
        """Close the CSV file (streaming mode) or write batch."""
        if self.mode == "streaming":
            if self._file is not None:
                self._file.flush()
                self._file.close()
                self._file = None
                self._writer = None
        else:
            # Batch mode: write all collected rows using pandas
            if self._batch_rows:
                df = pd.DataFrame(self._batch_rows, columns=COLUMN_NAMES)
                # Fill NaN/None with 0
                df = df.fillna(0)
                df.to_csv(self.output_path, index=False)
                self._row_count = len(df)
        
        logger.info(f"Wrote {self._row_count} flows to {self.output_path}")
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
    
    @property
    def rows_written(self) -> int:
        return self._row_count
