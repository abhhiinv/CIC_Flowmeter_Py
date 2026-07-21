# MODELS.md — Model Contract for CICFlowMeter Clone

This document describes the exact interface your model artifacts must conform to in order to work with this tool. The pipeline performs **inference only** — it never trains or modifies models.

---

## Required Files

Place all three files inside the `models/` directory at the project root:

```
models/
├── ensemble_model.pkl     # Trained classifier
├── scaler.pkl             # Fitted StandardScaler
└── label_encoder.pkl      # Fitted LabelEncoder
```

All three files must be serialized with `joblib`. Loading is handled by `cicflowmeter/predictor.py`.

---

## Model (`ensemble_model.pkl`)

- Must expose a `predict(X)` method compatible with the scikit-learn API
- Must expose a `predict_proba(X)` method for confidence scores (strongly recommended; confidence output is disabled if absent)
- Input `X` is a 2D numpy array of shape `(n_samples, 52)` — already scaled by the scaler
- Output of `predict()` must be an array of integer-encoded class labels matching the label encoder's encoding
- The reference implementation uses a `VotingClassifier` (soft voting) over Random Forest and XGBoost base learners, trained on CIC-IDS2017

---

## Scaler (`scaler.pkl`)

- Must be a fitted `StandardScaler` (or any scikit-learn transformer exposing `transform(X)`)
- Must have been fit on exactly the 52 features listed below, **in this exact order**
- If the scaler has a `feature_names_in_` attribute (set automatically when fit on a named DataFrame), the pipeline will use it to verify column order — this is the recommended approach

---

## Label Encoder (`label_encoder.pkl`)

- Must be a fitted `LabelEncoder`
- `inverse_transform()` is called on the model's integer output to recover class name strings
- The reference encoder maps 7 classes:

| Encoded Integer | Class Name |
|---|---|
| 0 | Bots |
| 1 | Brute Force |
| 2 | DDoS |
| 3 | DoS |
| 4 | Normal Traffic |
| 5 | Port Scanning |
| 6 | Web Attacks |

You can use a different set of classes as long as the encoder and model are consistent with each other.

---

## Feature Contract

The scaler and model must be trained on exactly these 52 features, in this order:

| # | Feature Name |
|---|---|
| 1 | Destination Port |
| 2 | Flow Duration |
| 3 | Total Fwd Packets |
| 4 | Total Length of Fwd Packets |
| 5 | Fwd Packet Length Max |
| 6 | Fwd Packet Length Min |
| 7 | Fwd Packet Length Mean |
| 8 | Fwd Packet Length Std |
| 9 | Bwd Packet Length Max |
| 10 | Bwd Packet Length Min |
| 11 | Bwd Packet Length Mean |
| 12 | Bwd Packet Length Std |
| 13 | Flow Bytes/s |
| 14 | Flow Packets/s |
| 15 | Flow IAT Mean |
| 16 | Flow IAT Std |
| 17 | Flow IAT Max |
| 18 | Flow IAT Min |
| 19 | Fwd IAT Total |
| 20 | Fwd IAT Mean |
| 21 | Fwd IAT Std |
| 22 | Fwd IAT Max |
| 23 | Fwd IAT Min |
| 24 | Bwd IAT Total |
| 25 | Bwd IAT Mean |
| 26 | Bwd IAT Std |
| 27 | Bwd IAT Max |
| 28 | Bwd IAT Min |
| 29 | Fwd Header Length |
| 30 | Bwd Header Length |
| 31 | Fwd Packets/s |
| 32 | Bwd Packets/s |
| 33 | Min Packet Length |
| 34 | Max Packet Length |
| 35 | Packet Length Mean |
| 36 | Packet Length Std |
| 37 | Packet Length Variance |
| 38 | FIN Flag Count |
| 39 | PSH Flag Count |
| 40 | ACK Flag Count |
| 41 | Average Packet Size |
| 42 | Subflow Fwd Bytes |
| 43 | Init_Win_bytes_forward |
| 44 | Init_Win_bytes_backward |
| 45 | act_data_pkt_fwd |
| 46 | min_seg_size_forward |
| 47 | Active Mean |
| 48 | Active Max |
| 49 | Active Min |
| 50 | Idle Mean |
| 51 | Idle Max |
| 52 | Idle Min |

> **Note:** Features 47–52 (Active/Idle statistics) are currently set to `0` by the flow extractor, as computing them requires activity-window tracking not yet implemented. Your model should be trained with these columns present but treated as always-zero during live inference.

---

## Bring Your Own Model

If you trained your own model on CIC-IDS2017 (or a compatible dataset), you can drop in replacement artifacts as long as you follow this contract. A minimal example:

```python
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Assume X_train (DataFrame with the 52 columns above) and y_train are ready

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_train)

le = LabelEncoder()
y_encoded = le.fit_transform(y_train)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_scaled, y_encoded)

joblib.dump(model,  'models/ensemble_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(le,     'models/label_encoder.pkl')
```

Custom model paths can also be passed directly to `Predictor`:

```python
from cicflowmeter.predictor import Predictor

p = Predictor(
    model_path='path/to/model.pkl',
    scaler_path='path/to/scaler.pkl',
    label_encoder_path='path/to/label_encoder.pkl'
)
p.load()
```
