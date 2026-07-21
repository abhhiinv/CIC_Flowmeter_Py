
---

# Real-Time Inference Pipeline

The end goal of this project is **not just offline PCAP-to-CSV conversion**.

The completed project must function as a real-time intrusion detection pipeline.

The pipeline should work as follows:

```
Live Network Traffic
        │
        ▼
Packet Capture
        │
        ▼
Flow Assembly
        │
        ▼
Feature Extraction (CICFlowMeter-compatible)
        │
        ▼
CSV Feature Vector
        │
        ▼
Feature Preprocessing (Scaler)
        │
        ▼
Machine Learning Model
        │
        ▼
Attack Prediction
        │
        ▼
Live Console / CSV / API Output
```

The implementation should support both:

* Offline PCAP processing
* Real-time packet capture

The existing PCAP processing code should remain fully functional.

---

# Live Packet Capture

Implement a live packet capture mode using Scapy.

The user should be able to specify:

* network interface
* packet count (optional)
* capture timeout
* BPF filter
* output CSV path

Example:

```
python main.py --live --interface Wi-Fi
```

or

```
python main.py --live --interface Ethernet --filter tcp
```

Packets should immediately be assigned to flows.

Flows should automatically expire after the configured timeout.

When a flow expires:

1. Calculate every feature.

2. Append one row to the CSV.

3. Immediately send the feature vector to the ML model.

The program must not wait until capture finishes.

---

# Machine Learning Integration

The project must include a prediction pipeline.

The following already exist:

```python
base = "D:/Academic/projects/cicClone/models"

model = joblib.load(f"{base}/ensemble_model.pkl")
scaler = joblib.load(f"{base}/scaler.pkl")
label_encoder = joblib.load(f"{base}/label_encoder.pkl")
```

Do not retrain any model.

Do not modify the saved model.

Only perform inference.

---

# Feature Compatibility

The generated feature vector must exactly match the feature order used during training.

The model should receive the exact same columns that were used when the model was trained.

If the generated DataFrame contains additional columns (such as Attack Type), remove them before inference.

If any expected feature is missing, generate it with value 0 instead of failing.

Before prediction:

1. Arrange columns in the exact training order.
2. Replace NaN with 0.
3. Convert all numeric columns to numeric types.
4. Scale features using the saved scaler.
5. Run prediction.
6. Decode labels using the saved label encoder.

---

# Prediction Output

For every completed flow print something similar to:

```
Flow:
192.168.1.10:53244 -> 8.8.8.8:53

Prediction:
BENIGN

Confidence:
98.74%
```

If the model supports `predict_proba()`, also display:

* predicted probability
* top three class probabilities

If probability is unavailable, skip confidence without raising errors.

---

# CSV Output

The CSV should continue to be written even when live prediction is enabled.

Each completed flow should immediately append one row.

Do not keep the entire dataset in memory.

---

# Performance

The system should be capable of:

* continuous live capture
* thousands of simultaneous flows
* automatic cleanup of expired flows
* low memory usage
* thread-safe flow management

Avoid blocking packet capture while feature extraction or prediction is running.

Use worker threads or queues if necessary.

---

# CLI

The final application should support commands similar to:

```
python main.py --pcap sample.pcap --output output.csv
```

```
python main.py --live --interface Wi-Fi
```

```
python main.py --live --interface Ethernet --predict
```

```
python main.py --live --interface Wi-Fi --output live.csv --predict
```

```
python main.py --live --interface Wi-Fi --filter "tcp port 80"
```

---

# Code Organization

Separate the project into independent modules.

Suggested structure:

```
capture.py
flow.py
feature_extractor.py
statistics.py
predictor.py
csv_writer.py
main.py
config.py
utils.py
```

The prediction code must be isolated inside `predictor.py`.

The flow extractor must not contain ML code.

The packet capture module must not contain feature calculation logic.

Maintain a clean separation of responsibilities.

---

# Validation

After implementation:

1. Run a live capture.
2. Generate CICFlowMeter-compatible features.
3. Write them to CSV.
4. Feed them into the saved model.
5. Display predictions in real time.
6. Verify that the feature order matches the training data exactly before inference.

Do not stop at packet capture or CSV generation. The completed project must function as an end-to-end real-time network intrusion detection system that captures live traffic, extracts CICFlowMeter-compatible flow features, writes them to CSV, and performs immediate machine learning inference on every completed flow.
