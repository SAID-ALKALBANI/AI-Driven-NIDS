import joblib
import numpy as np
import logging
from typing import List, Dict, Union, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IDSEngine:
    def __init__(self, model_path: str = 'ids_model_v2.pkl'):
        self.model_path = model_path
        self.model = self._load_model()
        
        self.attack_types = {
            0: "Normal",
            1: "DoS (Denial of Service)",
            2: "Probing (Scanning)",
            3: "R2L (Unauthorized Access)",
            4: "U2R (Privilege Escalation)"
        }
        
        self.severity_mapping = {
            0: "None",
            1: "High",
            2: "Medium",
            3: "Critical",
            4: "Critical"
        }

    def _load_model(self):
        try:
            model = joblib.load(self.model_path)
            logger.info(f"Successfully loaded model from {self.model_path}")
            return model
        except FileNotFoundError:
            logger.error(f"Model file not found: {self.model_path}. Please ensure the path is correct.")
            raise
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise

    def analyze_packet(self, features: Union[List[float], np.ndarray]) -> Dict[str, Any]:
        if self.model is None:
            raise ValueError("IDS Model is not loaded. Cannot analyze packets.")
            
        try:
            features_array = np.array(features).reshape(1, -1)
            prediction = int(self.model.predict(features_array)[0])
            
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(features_array)[0]
                confidence = float(max(probabilities)) * 100.0
            else:
                confidence = 100.0 
                
            result = {
                "type": self.attack_types.get(prediction, "Unknown Attack"),
                "confidence": round(confidence, 2),
                "severity": self.severity_mapping.get(prediction, "Unknown")
            }
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing packet features: {e}")
            return {
                "type": "Analysis Error",
                "confidence": 0.0,
                "severity": "Unknown",
                "error": str(e)
            }
