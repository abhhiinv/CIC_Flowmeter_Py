# CICFlowMeter Clone — Real-Time Network Intrusion Detection System

A Python implementation of CICFlowMeter that extracts network flow features from PCAP files or live traffic and performs real-time attack classification using a pre-trained machine learning model.

---

## Features

- **CICFlowMeter-compatible output** — generates exactly 52 numeric features + attack label per flow
- **Offline PCAP processing** — convert `.pcap` / `.pcapng` files to feature CSVs
- **Live packet capture** — sniff traffic from any network interface in real time
- **ML prediction** — classify each flow as Benign or one of 6 attack categories
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
numpy
```

### Install Dependencies

```bash
pip install scapy pandas joblib scikit-learn numpy
```

> **Windows users:** Install [Npcap](https://npcap.com/) with "WinPcap API-compatible mode" enabled for live capture support.

---

## Project Structure

```
cicClone/
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
│   ├── pcap_reader.py             # PCAP → PacketInfo parser
│   ├── csv_writer.py              # Streaming CSV output
│   └── stats_utils.py             # Statistics helper functions
├── models/                        # Pre-trained ML artifacts
│   ├── ensemble_model.pkl         # VotingClassifier model
│   ├── scaler.pkl                 # StandardScaler (52 features)
│   └── label_encoder.pkl          # LabelEncoder (7 classes)
├── cicflowmeter_converter.py      # Standalone PCAP-to-CSV converter
├── validate.py                    # Feature validation script
└── converter.py                   # Original baseline tool
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
| `--timeout SECONDS` | `120` | Flow inactivity timeout in seconds |
| `--label TEXT` | `Benign` | Default attack type label |
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
[Flow #1]
Flow:
  192.168.1.10:53244 -> 8.8.8.8:53

Prediction:
  Normal Traffic

Confidence:
  92.50%

Top probabilities:
  Normal Traffic: 92.50%
  DoS: 6.25%
  Port Scanning: 0.75%
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

Run the validation script to verify that all 53 columns are generated correctly:

```bash
# With a PCAP file
python validate.py sample.pcap

# Without a PCAP (uses synthetic packets)
python validate.py
```

The script checks:
1. All 53 columns are present
2. Column order matches CICFlowMeter exactly
3. All 52 numeric columns contain valid numbers
4. No NaN or None values exist
5. Prints every feature value for inspection

---

## Output Format

The CSV contains **53 columns** matching CICFlowMeter output:

| # | Column | Description |
|---|---|---|
| 1 | `Destination Port` | Destination port number |
| 2 | `Flow Duration` | Duration in microseconds |
| 3 | `Total Fwd Packets` | Forward packet count |
| 4 | `Total Length of Fwd Packets` | Total bytes in forward direction |
| 5–8 | `Fwd Packet Length Max/Min/Mean/Std` | Forward packet size statistics |
| 9–12 | `Bwd Packet Length Max/Min/Mean/Std` | Backward packet size statistics |
| 13 | `Flow Bytes/s` | Flow byte rate |
| 14 | `Flow Packets/s` | Flow packet rate |
| 15–18 | `Flow IAT Mean/Std/Max/Min` | Flow inter-arrival time statistics |
| 19–23 | `Fwd IAT Total/Mean/Std/Max/Min` | Forward IAT statistics |
| 24–28 | `Bwd IAT Total/Mean/Std/Max/Min` | Backward IAT statistics |
| 29–30 | `Fwd/Bwd Header Length` | Sum of IP+transport headers |
| 31–32 | `Fwd/Bwd Packets/s` | Directional packet rates |
| 33–37 | `Packet Length Min/Max/Mean/Std/Variance` | Overall packet size statistics |
| 38–40 | `FIN/PSH/ACK Flag Count` | TCP flag counts |
| 41 | `Average Packet Size` | Total bytes / total packets |
| 42 | `Subflow Fwd Bytes` | Forward payload bytes |
| 43–44 | `Init_Win_bytes_forward/backward` | Initial TCP window sizes |
| 45 | `act_data_pkt_fwd` | Forward packets with payload |
| 46 | `min_seg_size_forward` | Minimum forward segment size |
| 47–49 | `Active Mean/Max/Min` | Active period statistics |
| 50–52 | `Idle Mean/Max/Min` | Idle period statistics |
| 53 | `Attack Type` | Classification label |

---

## ML Model

The pre-trained model classifies flows into **7 categories**:

| Class | Description |
|---|---|
| Normal Traffic | Benign network activity |
| DDoS | Distributed Denial of Service |
| DoS | Denial of Service |
| Brute Force | Login brute force attempts |
| Port Scanning | Network reconnaissance |
| Web Attacks | HTTP-based attacks |
| Bots | Botnet traffic |

- **Model type:** VotingClassifier (ensemble)
- **Confidence scores:** Available via `predict_proba()`
- **Top-3 probabilities** are displayed for each prediction

> The model files in `models/` are pre-trained. This tool performs **inference only** — it does not retrain or modify the model.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      main.py (CLI)                      │
├──────────────┬──────────────────┬────────────────────────┤
│  Offline     │    Live Capture  │     Prediction         │
│  PCAP Mode   │    Mode          │     Pipeline           │
├──────────────┼──────────────────┼────────────────────────┤
│ pcap_reader  │   capture.py     │   predictor.py         │
│   ↓          │     ↓ (thread)   │     ↑                  │
│ PacketInfo   │   PacketInfo     │   scaled features      │
│   ↓          │     ↓ (queue)    │     ↑                  │
│ flow_manager │   flow_manager   │   feature dict         │
│   ↓          │     ↓            │     ↑                  │
│ Flow         │   Flow           │   Flow.get_features()  │
│   ↓          │     ↓            │                        │
│ csv_writer   │   csv_writer     │                        │
└──────────────┴──────────────────┴────────────────────────┘
```

**Separation of concerns:**
- `capture.py` — Packet capture only. No feature logic, no ML.
- `flow.py` / `flow_manager.py` — Flow assembly and features only. No ML, no capture.
- `predictor.py` — ML inference only. No flow logic, no capture.

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
- Check the flow timeout — very short sessions with `--timeout 5` may produce more flows.

### Model loading is slow

The ensemble model (~150 MB) takes a few seconds to load. This is a one-time cost at startup.

---

## License

This project is for academic and research purposes.
