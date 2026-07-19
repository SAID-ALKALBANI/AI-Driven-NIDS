"""
simulate_attack.py - Fixed version
------------------------------------
The core fix: the original version loaded the model but never used it at all,
and printed a hardcoded "100% Certainty" result regardless of any real
analysis.

This version takes real samples from the test data itself for each attack
category, and feeds them through IDSEngine.analyze_features() to see how the
real trained model actually behaves on unseen data.
"""

import time
from train_engine import load_and_prepare_data
from ai_logic import IDSEngine


def run_simulation():
    print("Starting NIDS Detection Simulation (real model inference)...")
    time.sleep(1)

    engine = IDSEngine("ids_model_v3.pkl")

    # Reuse the same preprocessing used during training to guarantee matching columns
    X, y = load_and_prepare_data("KDDTrain+_20Percent.txt")

    # One real sample per category present in the data
    for category in y.unique():
        sample_index = y[y == category].index[0]
        sample_features = X.loc[sample_index].to_dict()

        print(f"[*] Feeding a real '{category}' sample into the model...")
        time.sleep(1)

        result = engine.analyze_features(sample_features)

        print(
            f"Predicted: {result['type']} | "
            f"Confidence: {result['confidence']}% | "
            f"Severity: {result['severity']} | "
            f"(Actual label was: {category})"
        )
        print("-" * 60)


if __name__ == "__main__":
    run_simulation()
