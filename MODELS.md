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
- Input `X` is a 2D numpy array of shape `(n_samples, 46)` — already scaled by the scaler
- Output of `predict()` must be an array of integer-encoded class labels matching the label encoder's encoding
- The reference implementation uses a `VotingClassifier` (soft voting) over Random Forest and XGBoost base learners, trained on CIC-IDS2017

---

## Scaler (`scaler.pkl`)

- Must be a fitted `StandardScaler` (or any scikit-learn transformer exposing `transform(X)`)
- Must have been fit on exactly the 46 features listed below, **in this exact order**
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

The scaler and model must be trained on exactly these 46 features, in this order:

| # | Feature Name |
|---|---|
| 1 | Destination Port |
| 2 | Flow Duration |
| 3 | Total Fwd Packets |
| 4 | Total Backward Packets |
| 5 | Total Length of Fwd Packets |
| 6 | Total Length of Bwd Packets |
| 7 | Fwd Packet Length Max |
| 8 | Fwd Packet Length Min |
| 9 | Fwd Packet Length Mean |
| 10 | Fwd Packet Length Std |
| 11 | Bwd Packet Length Max |
| 12 | Bwd Packet Length Min |
| 13 | Bwd Packet Length Mean |
| 14 | Bwd Packet Length Std |
| 15 | Flow Bytes/s |
| 16 | Flow Packets/s |
| 17 | Flow IAT Mean |
| 18 | Flow IAT Std |
| 19 | Flow IAT Max |
| 20 | Flow IAT Min |
| 21 | Fwd IAT Mean |
| 22 | Fwd IAT Std |
| 23 | Fwd IAT Min |
| 24 | Bwd IAT Total |
| 25 | Bwd IAT Mean |
| 26 | Bwd IAT Max |
| 27 | Bwd IAT Min |
| 28 | Fwd Header Length |
| 29 | Bwd Header Length |
| 30 | Bwd Packets/s |
| 31 | Min Packet Length |
| 32 | Max Packet Length |
| 33 | Packet Length Mean |
| 34 | Packet Length Std |
| 35 | Packet Length Variance |
| 36 | FIN Flag Count |
| 37 | PSH Flag Count |
| 38 | ACK Flag Count |
| 39 | Init_Win_bytes_forward |
| 40 | Init_Win_bytes_backward |
| 41 | act_data_pkt_fwd |
| 42 | min_seg_size_forward |
| 43 | Active Mean |
| 44 | Active Max |
| 45 | Active Min |
| 46 | Idle Mean |


---

## Bring Your Own Model

If you trained your own model on CIC-IDS2017 (or a compatible dataset), you can drop in replacement artifacts as long as you follow this contract. A minimal example:

```python
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Assume X_train (DataFrame with the 46 columns above) and y_train are ready

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
