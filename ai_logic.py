"""
ai_logic.py - Fixed version
-----------------------------
Key fixes:
1. Loads the full "bundle" (model + label_encoder + feature_columns) saved by
   the new train_engine.py, instead of assuming a fixed numeric class mapping
   (0-4) that may not match training at all.
2. Accepts features as a dict with explicit column names, to guarantee the
   feature order always matches what the model was trained on (a very common
   source of silent bugs).
3. severity_mapping is now keyed by the text category name (Normal/DoS/...)
   instead of an assumed integer.
"""

import joblib
import logging
from typing import Dict, Any
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

SEVERITY_MAPPING = {
    "Normal": "None",
    "DoS": "High",
    "Probe": "Medium",
    "R2L": "Critical",
    "U2R": "Critical",
}


class IDSEngine:
    def __init__(self, model_path: str = "ids_model_v3.pkl"):
        self.model_path = model_path
        bundle = self._load_bundle()
        self.model = bundle["model"]
        self.label_encoder = bundle["label_encoder"]
        self.feature_columns = bundle["feature_columns"]

    def _load_bundle(self) -> Dict[str, Any]:
        try:
            bundle = joblib.load(self.model_path)
            logger.info(f"Successfully loaded model bundle from {self.model_path}")
            return bundle
        except FileNotFoundError:
            logger.error(f"Model file not found: {self.model_path}. Run train_engine.py first.")
            raise
        except Exception as e:
            logger.error(f"Failed to load model bundle: {e}")
            raise

    def analyze_raw(self, numeric_features: Dict[str, float], categorical_features: Dict[str, str]) -> Dict[str, Any]:
        """
        Convenience entry point for live traffic analysis (used by sniffer.py).

        train_engine.py one-hot encodes protocol_type/service/flag via
        pd.get_dummies(), producing columns named like "protocol_type_tcp",
        "service_http", "flag_SF". Live capture code naturally produces raw
        string values instead (e.g. protocol_type="tcp"), so this method
        converts those raw values into the same one-hot column names before
        calling analyze_features(), keeping that conversion logic in one
        place instead of duplicated in sniffer.py.
        """
        features = dict(numeric_features)
        for col_prefix, value in categorical_features.items():
            one_hot_col = f"{col_prefix}_{value}"
            features[one_hot_col] = 1
        return self.analyze_features(features)

    def analyze_features(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Accepts a dict of feature names (matching NSL-KDD names after encoding)
        instead of an unordered list of numbers - this prevents silent column
        order mismatches.
        """
        try:
            row = pd.DataFrame([features])
            # Fill in any missing columns with 0 (e.g. one-hot slots not present
            # in this particular sample)
            row = row.reindex(columns=self.feature_columns, fill_value=0)

            prediction_encoded = self.model.predict(row)[0]
            prediction_label = self.label_encoder.inverse_transform([prediction_encoded])[0]

            probabilities = self.model.predict_proba(row)[0]
            confidence = float(max(probabilities)) * 100.0

            return {
                "type": prediction_label,
                "confidence": round(confidence, 2),
                "severity": SEVERITY_MAPPING.get(prediction_label, "Unknown"),
            }
        except Exception as e:
            logger.error(f"Error analyzing packet features: {e}")
            return {
                "type": "Analysis Error",
                "confidence": 0.0,
                "severity": "Unknown",
                "error": str(e),
            }
