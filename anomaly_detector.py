"""
anomaly_detector.py
----------------------
Optional unsupervised anomaly-detection layer, meant to complement the
supervised RandomForest classifier in ai_logic.py.

Rationale: the RandomForest model can only recognize attack patterns it saw
during training. Live testing showed exactly this limitation - retraining on
much more data from the *same* distribution did not improve detection of
R2L/U2R attack subtypes absent from training (see the model-comparison
results in README). An Isolation Forest trained only on Normal traffic
instead learns the shape of "ordinary" connections and flags anything that
deviates significantly, regardless of whether that exact attack pattern was
ever labeled during training.

Honesty note: this does not guarantee catching every unseen attack type -
it only means "this looks statistically unusual compared to normal traffic",
which is a different (and complementary) signal from "this matches a known
attack pattern". Both can be wrong in different ways; combining them is
about triangulating, not achieving perfect detection.
"""

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    def __init__(self, contamination: float = 0.01):
        # contamination = expected proportion of anomalies in "normal-looking"
        # traffic; 0.01 is a conservative default and can be tuned later.
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.feature_columns = None

    def fit(self, X_normal: pd.DataFrame):
        """Fit using ONLY rows already known to be Normal traffic."""
        self.feature_columns = list(X_normal.columns)
        self.model.fit(X_normal)

    def score(self, features: dict) -> dict:
        """
        Score a single connection's features (same dict shape produced by
        flow_aggregator.py + the one-hot expansion in ai_logic.py).
        Returns a raw anomaly score (higher = more normal) and a boolean flag.
        """
        row = pd.DataFrame([features]).reindex(columns=self.feature_columns, fill_value=0)
        raw_score = self.model.decision_function(row)[0]  # higher = more normal
        is_anomaly = self.model.predict(row)[0] == -1       # -1 = anomaly, 1 = normal
        return {"anomaly_score": float(raw_score), "is_anomaly": bool(is_anomaly)}

    def save(self, path: str):
        joblib.dump({"model": self.model, "feature_columns": self.feature_columns}, path)

    @classmethod
    def load(cls, path: str) -> "AnomalyDetector":
        bundle = joblib.load(path)
        detector = cls()
        detector.model = bundle["model"]
        detector.feature_columns = bundle["feature_columns"]
        return detector
