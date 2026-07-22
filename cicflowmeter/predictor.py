#!/usr/bin/env python3
"""Predictor - ML inference on CICFlowMeter feature vectors.

Isolates all machine learning code from flow extraction.
Loads pre-trained model, scaler, and label encoder.
Performs inference only - never trains or modifies models.
"""

import logging
import warnings
import numpy as np
import pandas as pd
import joblib
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from .config import MODEL_PATH, SCALER_PATH, LABEL_ENCODER_PATH, MODEL_FEATURE_COLUMNS

# Suppress sklearn's joblib thread-context warning that appears during live capture
warnings.filterwarnings(
    'ignore',
    message=".*sklearn.utils.parallel.delayed.*",
    category=UserWarning
)

logger = logging.getLogger(__name__)


class Predictor:
    """Performs ML inference on CICFlowMeter-compatible feature vectors.
    
    Loads the saved ensemble model, scaler, and label encoder.
    Preprocesses feature vectors to match training format before prediction.
    """
    
    def __init__(self, model_path: Optional[str] = None,
                 scaler_path: Optional[str] = None,
                 label_encoder_path: Optional[str] = None) -> None:
        self.model_path = Path(model_path) if model_path else MODEL_PATH
        self.scaler_path = Path(scaler_path) if scaler_path else SCALER_PATH
        self.label_encoder_path = Path(label_encoder_path) if label_encoder_path else LABEL_ENCODER_PATH
        
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_columns = MODEL_FEATURE_COLUMNS
        self._loaded = False
    
    def load(self) -> None:
        """Load the model, scaler, and label encoder from disk.
        
        Call this once before making predictions.
        """
        logger.info(f"Loading model from {self.model_path}...")
        self.model = joblib.load(str(self.model_path))
        logger.info(f"Model type: {type(self.model).__name__}")
        
        logger.info(f"Loading scaler from {self.scaler_path}...")
        self.scaler = joblib.load(str(self.scaler_path))
        
        logger.info(f"Loading label encoder from {self.label_encoder_path}...")
        self.label_encoder = joblib.load(str(self.label_encoder_path))
        logger.info(f"Classes: {self.label_encoder.classes_.tolist()}")
        
        # Override feature columns from scaler if available
        if hasattr(self.scaler, 'feature_names_in_'):
            self.feature_columns = self.scaler.feature_names_in_.tolist()
            logger.info(f"Using {len(self.feature_columns)} features from scaler")
        
        # Force single-threaded execution on all sub-estimators.
        # The VotingClassifier wraps RandomForest/XGBoost which default to
        # n_jobs=-1 (all cores). In live capture, joblib spawns worker
        # processes that lose sklearn's thread-local config, causing the
        # UserWarning and eventual hang. Setting n_jobs=1 avoids this.
        self._force_single_threaded()
        
        self._loaded = True
        logger.info("Prediction pipeline ready.")
    
    def _force_single_threaded(self) -> None:
        """Set n_jobs=1 on the top-level model and all nested estimators.
        
        This prevents joblib from spawning worker processes during prediction,
        which causes threading issues in the live capture pipeline.
        """
        def _set_njobs(estimator) -> None:
            if hasattr(estimator, 'n_jobs'):
                estimator.n_jobs = 1
            # Recurse into VotingClassifier / Pipeline sub-estimators
            if hasattr(estimator, 'estimators_'):
                for est in estimator.estimators_:
                    _set_njobs(est)
            if hasattr(estimator, 'estimators'):  # unfitted list
                for _, est in estimator.estimators:
                    _set_njobs(est)
        
        _set_njobs(self.model)
        logger.info("Set n_jobs=1 on all sub-estimators for thread-safe prediction.")
    
    def _preprocess(self, features: Dict[str, Any]) -> np.ndarray:
        """Preprocess a single feature dict for prediction.
        
        Steps:
        1. Arrange columns in the exact training order
        2. Replace NaN with 0
        3. Convert all to numeric
        4. Scale using saved scaler
        
        Returns scaled feature array ready for model.predict().
        """
        # Build a single-row DataFrame with exact column order
        row = {}
        for col in self.feature_columns:
            value = features.get(col, 0)
            # Ensure numeric
            if value is None or (isinstance(value, float) and value != value):
                value = 0
            row[col] = [value]
        
        df = pd.DataFrame(row)
        
        # Convert to numeric, coerce errors to 0
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # Replace infinities with 0
        df = df.replace([np.inf, -np.inf], 0)
        
        # Scale features
        scaled = self.scaler.transform(df)
        
        return scaled
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Predict attack type for a single flow's feature vector.
        
        Args:
            features: Dict of feature name -> value (from Flow.get_features())
        
        Returns:
            Dict with:
                'label': predicted class name (str)
                'confidence': probability of predicted class (float or None)
                'probabilities': dict of class -> probability (or None)
        """
        if not self._loaded:
            self.load()
        
        # Preprocess
        scaled = self._preprocess(features)
        
        # Predict class
        prediction_encoded = self.model.predict(scaled)
        label = self.label_encoder.inverse_transform(prediction_encoded)[0]
        
        # Get probabilities if available
        confidence = None
        probabilities = None
        
        if hasattr(self.model, 'predict_proba'):
            try:
                proba = self.model.predict_proba(scaled)[0]
                classes = self.label_encoder.classes_
                confidence = float(np.max(proba))
                probabilities = {
                    cls: float(p) for cls, p in zip(classes, proba)
                }
            except Exception as e:
                logger.warning(f"Could not get probabilities: {e}")
        
        return {
            'label': label,
            'confidence': confidence,
            'probabilities': probabilities
        }
    
    def predict_batch(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict attack types for multiple flows at once.
        
        More efficient than calling predict() in a loop because
        it batches the scaler transform and model prediction.
        """
        if not self._loaded:
            self.load()
        
        if not features_list:
            return []
        
        # Build DataFrame for all flows
        rows = []
        for features in features_list:
            row = {}
            for col in self.feature_columns:
                value = features.get(col, 0)
                if value is None or (isinstance(value, float) and value != value):
                    value = 0
                row[col] = value
            rows.append(row)
        
        df = pd.DataFrame(rows)
        
        # Convert to numeric, replace NaN/inf
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        df = df.replace([np.inf, -np.inf], 0)
        
        # Scale
        scaled = self.scaler.transform(df)
        
        # Predict
        predictions_encoded = self.model.predict(scaled)
        labels = self.label_encoder.inverse_transform(predictions_encoded)
        
        # Probabilities
        results = []
        probas = None
        if hasattr(self.model, 'predict_proba'):
            try:
                probas = self.model.predict_proba(scaled)
            except Exception:
                pass
        
        classes = self.label_encoder.classes_
        for i, label in enumerate(labels):
            result = {'label': label, 'confidence': None, 'probabilities': None}
            if probas is not None:
                result['confidence'] = float(np.max(probas[i]))
                result['probabilities'] = {
                    cls: float(p) for cls, p in zip(classes, probas[i])
                }
            results.append(result)
        
        return results
    
    @staticmethod
    def format_prediction(src_ip: str, src_port: int,
                          dst_ip: str, dst_port: int,
                          result: Dict[str, Any]) -> str:
        """Format a prediction result for console display."""
        lines = []
        lines.append(f"Flow:")
        lines.append(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        lines.append(f"")
        lines.append(f"Prediction:")
        lines.append(f"  {result['label']}")
        
        if result['confidence'] is not None:
            lines.append(f"")
            lines.append(f"Confidence:")
            lines.append(f"  {result['confidence'] * 100:.2f}%")
        
        if result['probabilities'] is not None:
            lines.append(f"")
            lines.append(f"Top probabilities:")
            # Sort by probability, show top 3
            sorted_probs = sorted(
                result['probabilities'].items(),
                key=lambda x: x[1], reverse=True
            )[:3]
            for cls, prob in sorted_probs:
                lines.append(f"  {cls}: {prob * 100:.2f}%")
        
        return "\n".join(lines)
