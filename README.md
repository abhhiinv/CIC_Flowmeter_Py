# CICFlowMeter Clone — Real-Time Network Intrusion Detection System

A Python implementation of CICFlowMeter that extracts network flow features from PCAP files or live traffic and performs real-time attack classification using a pre-trained machine learning model.

---

## Features

- **CICFlowMeter-compatible output** — generates 46 numeric features + attack label per flow (CSV)
- **40-feature ML pipeline** — model consumes a curated subset of 40 features
- **Offline PCAP processing** — convert `.pcap` / `.pcapng` files to feature CSVs
- **Live packet capture** — sniff traffic from any network interface in real time
- **ML prediction** — classify each flow as Normal Traffic or one of 4 attack categories
- **Port Scan Detector** (`--psd`) — cross-flow detection that catches scans the per-flow model misses
- **IPv6 support** — correctly handles IPv6 flows including extension headers
- **Streaming architecture** — constant memory, writes flows to CSV as they complete
- **Multiprocessing** — parallel chunk processing for multi-GB PCAPs
- **Directory batch mode** — process entire folders of PCAPs at once

---

## Requirements

- **Python 3.10+**
- **Administrator / root privileges** (required for live capture only)
- **Npcap** (Windows) or **libpcap** (Linux/macOS) for live capture

### Python Dependencies

```
scapy
pandas
joblib
scikit-learn
xgboost
numpy
```

### Install Dependencies

```bash
pip install scapy pandas joblib scikit-learn xgboost numpy
```

> **Windows users:** Install [Npcap](https://npcap.com/) with "WinPcap API-compatible mode" enabled for live capture support.

---

## Project Structure

```
CIC_Flowmeter_Py/
├── main.py                        # Main CLI entry point
├── cicflowmeter/                  # Core package
│   ├── __init__.py
│   ├── config.py                  # Configuration constants & model paths
│   ├── capture.py                 # Live packet capture (Scapy sniff)
│   ├── predictor.py               # ML inference pipeline
│   ├── packet_info.py             # Per-packet metadata dataclass
│   ├── flow_key.py                # Bidirectional 5-tuple flow identifier
│   ├── flow.py                    # Flow class & feature extraction
│   ├── flow_manager.py            # Flow lifecycle & timeout management
│   ├── pcap_reader.py             # PCAP → PacketInfo parser (IPv4 & IPv6)
│   ├── portscan_detector.py       # Sliding-window cross-flow port scan detector
│   ├── csv_writer.py              # Streaming CSV output
│   └── stats_utils.py             # Statistics helper functions
├── models/                        # Pre-trained ML artifacts
│   ├── ensemble_model.pkl         # VotingClassifier (RF + XGBoost)
│   ├── scaler.pkl                 # RobustScaler (40 features)
│   └── label_encoder.pkl          # LabelEncoder (5 classes)
├── cicflowmeter_converter.py      # Standalone PCAP-to-CSV converter
├── validate.py                    # Feature validation script
└── PROGRESS.md                    # Detailed change log & roadmap
```

---

## Quick Start

### 1. Process a PCAP File

```bash
python main.py --pcap capture.pcap --output flows.csv
```

### 2. Process a PCAP with ML Prediction

```bash
python main.py --pcap capture.pcap --output flows.csv --predict
```

### 3. Live Capture with Prediction

```bash
# Windows: run Command Prompt as Administrator
# Linux/macOS: use sudo

python main.py --live --interface Wi-Fi --output live_flows.csv --predict
```

---

## Usage

### Command Reference

```
python main.py [MODE] [OPTIONS]
```

#### Modes (mutually exclusive)

| Flag | Description |
|---|---|
| `--pcap FILE` | Process a PCAP file offline |
| `--live` | Capture packets from a live network interface |
| `--list-interfaces` | List available network interfaces and exit |

#### Common Options

| Flag | Default | Description |
|---|---|---|
| `--output FILE`, `-o` | Auto-generated | Output CSV file path |
| `--predict` | Off | Enable ML attack classification |
| `--psd` | Off | Enable cross-flow Port Scan Detector (independent of `--predict`) |
| `--timeout SECONDS` | `30` | Flow inactivity timeout in seconds |
| `--label TEXT` | `Normal Traffic` | Default attack type label |
| `--debug` | Off | Enable verbose debug logging |

#### Live Capture Options

| Flag | Default | Description |
|---|---|---|
| `--interface NAME`, `-i` | *Required* | Network interface (e.g. `Wi-Fi`, `Ethernet`) |
| `--filter BPF` | None | Berkeley Packet Filter (e.g. `"tcp port 80"`) |
| `--count N` | `0` (unlimited) | Max number of packets to capture |
| `--capture-timeout SECS` | None (forever) | Stop capture after N seconds |

---

## Examples

### List available interfaces

```bash
python main.py --list-interfaces
```

Output:
```
Available network interfaces:
----------------------------------------
  1. Wi-Fi
     Intel(R) Wi-Fi 6 AX201 160MHz
  2. Ethernet
     Realtek PCIe GbE Family Controller
  ...
```

### Offline PCAP to CSV (no prediction)

```bash
python main.py --pcap traffic.pcap --output traffic_flows.csv
```

### Offline PCAP with attack detection

```bash
python main.py --pcap suspicious.pcap --output results.csv --predict
```

Example output per flow:
```
--------------------------------------------------
[Flow #1] 2026-08-26 23:47:24 | 192.168.1.10:53244 -> 8.8.8.8:53 | 4 pkts | Duration: 21980 us
  Prediction  : Normal Traffic
  Confidence  : 92.50%
  Probabilities:
    Normal Traffic: 92.50%
    DoS:             6.25%
    Port Scan:       0.75%
--------------------------------------------------
```

### Live capture — HTTP traffic only

```bash
python main.py --live --interface Wi-Fi --filter "tcp port 80" --output http_flows.csv --predict
```

### Live capture — 60 second session

```bash
python main.py --live --interface Ethernet --capture-timeout 60 --output session.csv --predict
```

### Live capture — capture 1000 packets then stop

```bash
python main.py --live --interface Wi-Fi --count 1000 --output sample.csv
```

Press **Ctrl+C** at any time during live capture to stop. All active flows will be flushed and written to CSV.

### Port Scan Detector only (no ML model needed)

```bash
python main.py --live --interface Wi-Fi --psd
```

### ML prediction + Port Scan Detector together

```bash
python main.py --live --interface Wi-Fi --predict --psd
```

---

## Port Scan Detector (`--psd`)

The ML model classifies flows individually and **cannot detect port scans** — each single probe (SYN + RST/SYN-ACK) looks identical to normal traffic. The `--psd` flag enables a cross-flow detector that tracks unique `(dst_ip, dst_port)` contacts per source IP within a sliding time window.

| Parameter | Default | Description |
|---|---|---|
| Window | 60 seconds | Sliding time window for counting probe contacts |
| Threshold | 15 unique ports | Number of unique `(dst_ip, dst_port)` pairs before flagging |

**Alert behaviour:**
- The alert is printed **once per scan episode** (when the threshold is first crossed).
- Subsequent flows from the same attacker during the episode are labelled `Port Scan` in the CSV without reprinting the alert.
- The episode resets once probe entries age out of the 60-second window.

**Works on all address types** — including IPv6 link-local (`fe80::`) port scans that the ML model never sees (internal traffic is filtered from ML).

**Can be used without `--predict`** — the detector runs independently of the ML model and requires no model files.

---

## Standalone PCAP Converter

For batch processing without ML prediction, you can also use the standalone converter:

```bash
# Single file
python cicflowmeter_converter.py input.pcap output.csv

# Directory — separate CSV per PCAP
python cicflowmeter_converter.py --input-dir ./pcaps --output-dir ./csvs

# Directory — merge all into one CSV
python cicflowmeter_converter.py --input-dir ./pcaps --output-dir ./csvs --merge

# Custom flow timeout and label
python cicflowmeter_converter.py input.pcap output.csv --timeout 60 --label "DDoS"
```

---

## Validation

### Feature validation script

Verifies all 47 CSV columns are generated correctly:

```bash
# With a PCAP file
python validate.py sample.pcap

# Without a PCAP (uses synthetic packets)
python validate.py
```

The script checks:
1. All 47 columns are present and in the correct order
2. All 46 numeric columns contain valid numbers
3. No NaN or None values
4. Prints every feature value for inspection

---

## Output Format

The CSV contains **47 columns** — 46 numeric features (always written) + label:

| # | Column | Description |
|---|---|---|
| 1 | `Destination Port` | Destination port number |
| 2 | `Flow Duration` | Duration in microseconds |
| 3 | `Total Fwd Packets` | Forward packet count |
| 4 | `Total Backward Packets` | Backward packet count |
| 5 | `Total Length of Fwd Packets` | Total bytes in forward direction |
| 6 | `Total Length of Bwd Packets` | Total bytes in backward direction |
| 7–10 | `Fwd Packet Length Max/Min/Mean/Std` | Forward packet size statistics |
| 11–14 | `Bwd Packet Length Max/Min/Mean/Std` | Backward packet size statistics |
| 15 | `Flow Bytes/s` | Flow byte rate |
| 16 | `Flow Packets/s` | Flow packet rate |
| 17–20 | `Flow IAT Mean/Std/Max/Min` | Flow inter-arrival time statistics (μs) |
| 21–23 | `Fwd IAT Mean/Std/Min` | Forward IAT statistics (μs) |
| 24–27 | `Bwd IAT Total/Mean/Max/Min` | Backward IAT statistics (μs) |
| 28–29 | `Fwd/Bwd Header Length` | Sum of TCP/UDP header bytes per direction |
| 30 | `Bwd Packets/s` | Backward packet rate |
| 31–35 | `Min/Max Packet Length, Mean/Std/Variance` | Overall packet size statistics |
| 36–38 | `FIN/PSH/ACK Flag Count` | TCP flag counts (all packets, both directions) |
| 39–40 | `Init_Win_bytes_forward/backward` | Initial TCP window size per direction |
| 41 | `act_data_pkt_fwd` | Forward packets carrying payload (payload > 0) |
| 42 | `min_seg_size_forward` | Minimum TCP header length across forward packets |
| 43–45 | `Active Mean/Max/Min` | Active burst duration statistics (μs) |
| 46 | `Idle Mean` | Mean idle gap duration (μs) |
| 47 | `Attack Type` | Classification label |

> **Note:** The ML model consumes 40 of these 46 features. The full 46 are always written to CSV for logging and analysis. See the "ML Model" section below for which features are used.

---

## ML Model

### Classification

The pre-trained model classifies flows into **5 categories**:

| Class | Description |
|---|---|
| Normal Traffic | Benign network activity |
| DoS | Denial of Service |
| DDoS | Distributed Denial of Service |
| Brute Force | Login brute force (FTP, SSH, HTTP) |
| Port Scan | Network port reconnaissance |

- **Model type:** VotingClassifier (Random Forest + XGBoost soft voting ensemble)
- **Scaler:** RobustScaler (fitted on CICIDS2017 training data)
- **Training dataset:** CICIDS2017 (preprocessed, ~2.5M flows)
- **Confidence scores:** Available via `predict_proba()`

> The model files in `models/` are pre-trained. This tool performs **inference only** — it does not retrain or modify the model.

### 40 Features Fed to the Model

The model was trained on these 40 features (in this exact order):

| # | Feature |
|---|---|
| 1 | Flow Duration |
| 2 | Total Fwd Packets |
| 3 | Total Backward Packets |
| 4 | Total Length of Fwd Packets |
| 5 | Fwd Packet Length Max |
| 6 | Fwd Packet Length Min |
| 7 | Fwd Packet Length Mean |
| 8 | Fwd Packet Length Std |
| 9 | Bwd Packet Length Max |
| 10 | Bwd Packet Length Mean |
| 11 | Bwd Packet Length Std |
| 12 | Flow Bytes/s |
| 13 | Flow Packets/s |
| 14 | Flow IAT Mean |
| 15 | Flow IAT Std |
| 16 | Flow IAT Max |
| 17 | Flow IAT Min |
| 18 | Fwd IAT Std |
| 19 | Fwd IAT Min |
| 20 | Bwd IAT Total |
| 21 | Bwd IAT Max |
| 22 | Bwd IAT Min |
| 23 | Fwd Header Length |
| 24 | Bwd Header Length |
| 25 | Bwd Packets/s |
| 26 | Min Packet Length |
| 27 | Max Packet Length |
| 28 | Packet Length Mean |
| 29 | Packet Length Std |
| 30 | FIN Flag Count |
| 31 | PSH Flag Count |
| 32 | ACK Flag Count |
| 33 | Init_Win_bytes_forward |
| 34 | Init_Win_bytes_backward |
| 35 | act_data_pkt_fwd |
| 36 | min_seg_size_forward |
| 37 | Active Mean |
| 38 | Active Max |
| 39 | Active Min |
| 40 | Idle Mean |

Features written to CSV but **not** fed to the model: `Destination Port`, `Total Length of Bwd Packets`, `Bwd Packet Length Min`, `Fwd IAT Mean`, `Bwd IAT Mean`, `Packet Length Variance`.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      main.py (CLI)                       │
├──────────────┬──────────────────┬────────────────────────┤
│  Offline     │    Live Capture  │     Prediction         │
│  PCAP Mode   │    Mode          │     Pipeline           │
├──────────────┼──────────────────┼────────────────────────┤
│ pcap_reader  │   capture.py     │   predictor.py         │
│   ↓          │     ↓ (thread)   │     ↑                  │
│ PacketInfo   │   PacketInfo     │   40 scaled features   │
│   ↓          │     ↓ (queue)    │     ↑                  │
│ flow_manager │   flow_manager   │   feature dict (46)    │
│   ↓          │     ↓            │     ↑                  │
│ Flow         │   Flow           │   Flow.get_features()  │
│   ↓          │     ↓            │                        │
│ csv_writer   │   csv_writer     │  portscan_detector     │
└──────────────┴──────────────────┴────────────────────────┘
```

**Separation of concerns:**
- `capture.py` — Packet capture only. No feature logic, no ML.
- `flow.py` / `flow_manager.py` — Flow assembly and feature extraction. No ML, no capture.
- `predictor.py` — ML inference only. Selects 40 features from the 46-feature dict.
- `portscan_detector.py` — Stateful cross-flow scan detection. No ML dependency.

---

## Implementation Notes

### Packet length
Uses the **IP total length** field (`ip_layer.len`) — includes IP header + transport header + payload. Does not include the Ethernet frame overhead. For IPv6: `40 + plen`.

### Header length features
`Fwd Header Length` and `Bwd Header Length` sum the **TCP/UDP header bytes** only (not IP header), matching the original Java CICFlowMeter behaviour.

### Flow direction
TCP flows use SYN/SYN-ACK detection to assign the client as forward:
- SYN-only → packet sender is the client (forward).
- SYN-ACK seen first (asymmetric capture) → direction is swapped so client remains forward.
- Non-TCP falls back to first-seen heuristic.

### Active / Idle periods
Uses a **5-second** activity timeout (matching CICFlowMeter default). Trailing active bursts (after the last idle gap) are **not** recorded, matching Java behaviour. Flows with no idle gap return `Active Mean = 0`.

### FIN and RST handling
TCP flows are **terminated on the first FIN packet** (from either direction), matching Java CICFlowMeter behaviour. The trailing ACK/FIN/ACK exchange then forms a new short "appendix" flow — just as in the original tool. This ensures packet counts, IAT values, flag counts, and Active/Idle distributions align with the CICIDS2017 training data.

**RST** does not terminate flows. Flows reset by RST expire via the inactivity timeout. This is a known minor difference from some CICFlowMeter configurations.

### IPv6 extension headers
Extension headers (Routing, Fragment, Hop-by-Hop, etc.) are handled by using Scapy's `haslayer(TCP/UDP)` which walks the full header chain, ensuring IPv6 TCP/UDP flows are not silently dropped as `OTHER_*`.

---

## Troubleshooting

### Permission denied during live capture

Live capture requires administrator privileges:
- **Windows:** Right-click Command Prompt → "Run as administrator"
- **Linux/macOS:** `sudo python main.py --live --interface eth0`

### Npcap not found (Windows)

Download and install [Npcap](https://npcap.com/). During installation, check **"Install Npcap in WinPcap API-compatible mode"**.

### Interface not found

Run `python main.py --list-interfaces` to see available interface names. Use the exact name shown (e.g. `Wi-Fi`, not `wifi`).

### No flows detected from PCAP

- Ensure the PCAP contains IP traffic (TCP/UDP). Non-IP packets (ARP, etc.) are skipped.
- Very short sessions may time out before completing — try `--timeout 5` to lower the expiry threshold.

### Model loading is slow

The ensemble model (RF + XGBoost) takes a few seconds to deserialise on first use. This is a one-time startup cost.

### RobustScaler feature name warning

If you see `X does not have valid feature names, but RobustScaler was fitted with feature names`, this is silenced in current code by passing the feature DataFrame (not `.values`) to `scaler.transform()`. If you still see it, ensure you are running the latest `predictor.py`.

---

## License

This project is for academic and research purposes.