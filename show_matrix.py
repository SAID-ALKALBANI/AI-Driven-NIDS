"""
show_matrix.py - Fixed version (with external test set evaluation)
----------------------------------------------------------------------
In addition to the internal 80/20 split evaluation (same distribution as
training data), this version also evaluates the model on the official
KDDTest+.txt file, which the model has never seen at all during training.
This gives an honest picture of how well the model generalizes to unseen
traffic, not just to held-out data drawn from the same source file.
"""

import argparse
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report

from train_engine import load_and_prepare_data


def evaluate(title, model, label_encoder, feature_columns, X, y_encoded):
    X = X.reindex(columns=feature_columns, fill_value=0)
    y_pred = model.predict(X)

    # Always report against the FULL set of known classes (0..n-1), even if a
    # particular test file happens not to contain every category (e.g. no
    # U2R samples at all). Without this, classification_report crashes when
    # the number of classes present doesn't match len(label_encoder.classes_).
    all_labels = list(range(len(label_encoder.classes_)))

    print("\n" + "=" * 20 + f" {title} - Confusion Matrix " + "=" * 20)
    print(confusion_matrix(y_encoded, y_pred, labels=all_labels))
    print("=" * 68)

    print("\n" + "=" * 18 + f" {title} - Classification Report " + "=" * 17)
    print(classification_report(
        y_encoded, y_pred,
        labels=all_labels,
        target_names=label_encoder.classes_,
        digits=4, zero_division=0,
    ))
    print("=" * 68 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Evaluate a trained NIDS model.")
    parser.add_argument("--model", default="ids_model_v3.pkl", help="Path to the trained model bundle")
    parser.add_argument("--train-data", default="KDDTrain+_20Percent.txt",
                         help="Training file used for the internal 80/20 split comparison")
    parser.add_argument("--test-data", default="KDDTest+.txt",
                         help="Official unseen test file")
    args = parser.parse_args()

    bundle = joblib.load(args.model)
    model = bundle["model"]
    label_encoder = bundle["label_encoder"]
    feature_columns = bundle["feature_columns"]

    print(f"[*] Evaluating model: {args.model}\n")

    # --- 1. Internal held-out split (same source file as training) ---
    X_train_file, y_train_file = load_and_prepare_data(args.train_data)
    X_train_file = X_train_file.reindex(columns=feature_columns, fill_value=0)
    y_train_encoded = label_encoder.transform(y_train_file)

    _, X_test_internal, _, y_test_internal = train_test_split(
        X_train_file, y_train_encoded, test_size=0.2, random_state=42, stratify=y_train_encoded
    )
    evaluate("Internal 80/20 split", model, label_encoder, feature_columns, X_test_internal, y_test_internal)

    # --- 2. Fully external, never-seen-before official test set ---
    try:
        X_ext, y_ext = load_and_prepare_data(args.test_data)
        y_ext_encoded = label_encoder.transform(y_ext)
        evaluate("Official KDDTest+ (unseen data)", model, label_encoder, feature_columns, X_ext, y_ext_encoded)
    except FileNotFoundError:
        print(f"[!] '{args.test_data}' not found - skipping external evaluation.")


if __name__ == "__main__":
    main()
