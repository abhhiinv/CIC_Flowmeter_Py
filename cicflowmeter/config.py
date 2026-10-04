#!/usr/bin/env python3
"""Configuration constants for the CICFlowMeter pipeline.

Centralises all tuneable parameters so they can be changed in one place.
"""

import os
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"

MODEL_PATH = MODEL_DIR / "ensemble_model.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder.pkl"

# ── Flow settings ────────────────────────────────────────────────────────
FLOW_TIMEOUT_SECONDS = 30.0         # Inactivity timeout before flow expires
ACTIVITY_TIMEOUT_US = 5_000_000.0   # 5 s in microseconds (active/idle split)

# ── Live capture defaults ────────────────────────────────────────────────
DEFAULT_CAPTURE_TIMEOUT = None      # None = capture forever
DEFAULT_PACKET_COUNT = 0            # 0 = unlimited
DEFAULT_BPF_FILTER = ""             # Empty = capture everything

# ── Performance ──────────────────────────────────────────────────────────
FLOW_CLEANUP_INTERVAL = 5.0         # Seconds between timeout sweeps in live mode
CSV_FLUSH_INTERVAL = 100            # Rows between explicit CSV flushes

# ── Feature columns (40 numeric features fed to model – excludes "Attack Type") ──
# Removed vs. the 46-feature extractor output:
#   Destination Port, Total Length of Bwd Packets, Bwd Packet Length Min,
#   Fwd IAT Mean, Bwd IAT Mean, Packet Length Variance
MODEL_FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Std",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd Header Length",
    "Bwd Header Length",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Max",
    "Idle Mean",
]