"""
train_engine.py - Fixed version
--------------------------------
Key fixes compared to the original version:
1. Explicit column names for all 43 official NSL-KDD fields, instead of relying
   on raw column positions.
2. Separated the "difficulty_level" column (previously misused as the label)
   from the actual "label" column.
3. Grouped detailed attack labels (neptune, satan, ...) into the 5 standard
   categories: Normal, DoS, Probe, R2L, U2R - matching what ai_logic.py expects.
4. Properly encoded categorical features (protocol_type, service, flag)
   instead of dropping them entirely.
5. Saved the feature column order together with the model, to guarantee
   consistency at inference time.
6. Added a full classification report instead of relying on accuracy alone,
   since accuracy is misleading on imbalanced data.
"""

import argparse
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
from anomaly_detector import AnomalyDetector

# --- 1. Official NSL-KDD column names (41 features + label + difficulty_level) ---
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level",
]

# --- 2. Map detailed attack labels to the 5 standard categories ---
ATTACK_CATEGORY_MAP = {
    "normal": "Normal",
    "neptune": "DoS", "back": "DoS", "land": "DoS", "pod": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "mailbomb": "DoS", "apache2": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe",
    "mscan": "Probe", "saint": "Probe",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L",
    "phf": "R2L", "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L",
    "sendmail": "R2L", "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "worm": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R",
    "httptunnel": "U2R", "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
}


def load_and_prepare_data(path: str) -> tuple[pd.DataFrame, pd.Series]:
    print("[*] Loading NSL-KDD dataset...")
    data = pd.read_csv(path, header=None, names=COLUMN_NAMES)

    # Drop the difficulty column - it is a difficulty score, not a label
    data = data.drop(columns=["difficulty_level"])

    # Collapse detailed attack labels into the 5 main categories
    data["label"] = data["label"].str.strip().map(ATTACK_CATEGORY_MAP).fillna("Unknown")

    y = data["label"]
    X = data.drop(columns=["label"])

    # Encode categorical features (these were being dropped entirely before)
    categorical_cols = ["protocol_type", "service", "flag"]
    X = pd.get_dummies(X, columns=categorical_cols)

    return X, y


def main():
    parser = argparse.ArgumentParser(description="Train the NIDS Random Forest model.")
    parser.add_argument(
        "--data", default="KDDTrain+_20Percent.txt",
        help="Path to the NSL-KDD training file (default: KDDTrain+_20Percent.txt)"
    )
    parser.add_argument(
        "--output", default="ids_model_v3.pkl",
        help="Path to save the trained model bundle (default: ids_model_v3.pkl)"
    )
    parser.add_argument(
        "--anomaly-output", default="anomaly_model.pkl",
        help="Path to save the unsupervised anomaly-detection model (default: anomaly_model.pkl)"
    )
    parser.add_argument(
        "--skip-anomaly", action="store_true",
        help="Skip training the anomaly-detection layer (only train the RandomForest classifier)"
    )
    args = parser.parse_args()

    X, y = load_and_prepare_data(args.data)

    # Encode text labels (Normal/DoS/Probe/R2L/U2R) into numbers for training
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    print(f"[*] Training started on '{args.data}'... please wait.")
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",  # handles class imbalance (U2R is very rare)
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[+] Overall Accuracy: {acc * 100:.2f}%")
    print("\n[+] Detailed classification report (per attack category):")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_, zero_division=0))

    # Save the model + encoders + feature columns together to keep them in sync
    joblib.dump({
        "model": model,
        "label_encoder": label_encoder,
        "feature_columns": list(X.columns),
    }, args.output)
    print(f"[+] Model bundle saved as '{args.output}'")

    if not args.skip_anomaly:
        print(f"\n[*] Training unsupervised anomaly detector on Normal-only traffic...")
        normal_label_encoded = label_encoder.transform(["Normal"])[0]
        X_normal_only = X_train[y_train == normal_label_encoded]

        detector = AnomalyDetector(contamination=0.01)
        detector.fit(X_normal_only)
        detector.save(args.anomaly_output)
        print(f"[+] Anomaly detector trained on {len(X_normal_only)} Normal samples, "
              f"saved as '{args.anomaly_output}'")


if __name__ == "__main__":
    main()
