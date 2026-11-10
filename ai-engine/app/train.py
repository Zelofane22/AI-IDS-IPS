"""Train the Random Forest used by the AI-IDS-IPS prototype.

Data sources, in order of preference:
  1. --data <csv> : user-supplied dataset. A CIC-IDS2017 style CSV (Label
     column + standard CIC columns) is mapped to the canonical feature schema;
     a CSV already using the canonical columns is used as-is.
  2. --demo       : synthetic dataset, explicitly labelled as demonstration
     data. Never present its metrics as real experimental results.

The saved Joblib bundle contains the fitted model, the exact feature order and
the imputation medians, so predict.py cannot diverge from training.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from features import (
    ATTACK_LABEL,
    BENIGN_LABEL,
    CIC_LABEL_COLUMN,
    FEATURES,
    LABEL_COLUMN,
    build_feature_matrix,
    resolve_labels,
)

CIC_COLUMN_MAP = {
    "duration_ms": "Flow Duration",
    "packets_fwd": "Total Fwd Packets",
    "packets_bwd": "Total Backward Packets",
    "bytes_fwd": "Total Length of Fwd Packets",
    "bytes_bwd": "Total Length of Bwd Packets",
    "bytes_per_s": "Flow Bytes/s",
    "packets_per_s": "Flow Packets/s",
    "mean_pkt_size": "Packet Length Mean",
    "min_pkt_size": "Min Packet Length",
    "max_pkt_size": "Max Packet Length",
    "stddev_pkt_size": "Packet Length Std",
    "dst_port": "Destination Port",
    "protocol_num": "Protocol",
}


def _clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns=lambda c: str(c).lstrip("\ufeff").strip())
    return df


def _load_cic(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in CIC_COLUMN_MAP.values() if c not in df.columns]
    if missing:
        raise ValueError(
            "CSV is neither in canonical format nor a recognizable CIC-IDS2017 "
            f"sample (missing: {missing})"
        )
    out = pd.DataFrame(index=df.index)
    out["duration_ms"] = pd.to_numeric(df[CIC_COLUMN_MAP["duration_ms"]], errors="coerce") / 1000.0
    packets_fwd = pd.to_numeric(df[CIC_COLUMN_MAP["packets_fwd"]], errors="coerce")
    packets_bwd = pd.to_numeric(df[CIC_COLUMN_MAP["packets_bwd"]], errors="coerce")
    bytes_fwd = pd.to_numeric(df[CIC_COLUMN_MAP["bytes_fwd"]], errors="coerce")
    bytes_bwd = pd.to_numeric(df[CIC_COLUMN_MAP["bytes_bwd"]], errors="coerce")
    out["packets"] = packets_fwd.fillna(0) + packets_bwd.fillna(0)
    out["bytes"] = bytes_fwd.fillna(0) + bytes_bwd.fillna(0)
    out["bytes_per_s"] = pd.to_numeric(df[CIC_COLUMN_MAP["bytes_per_s"]], errors="coerce")
    out["packets_per_s"] = pd.to_numeric(df[CIC_COLUMN_MAP["packets_per_s"]], errors="coerce")
    out["mean_pkt_size"] = pd.to_numeric(df[CIC_COLUMN_MAP["mean_pkt_size"]], errors="coerce")
    out["min_pkt_size"] = pd.to_numeric(df[CIC_COLUMN_MAP["min_pkt_size"]], errors="coerce")
    out["max_pkt_size"] = pd.to_numeric(df[CIC_COLUMN_MAP["max_pkt_size"]], errors="coerce")
    out["stddev_pkt_size"] = pd.to_numeric(df[CIC_COLUMN_MAP["stddev_pkt_size"]], errors="coerce")
    out["dst_port"] = pd.to_numeric(df[CIC_COLUMN_MAP["dst_port"]], errors="coerce")
    out["protocol_num"] = pd.to_numeric(df[CIC_COLUMN_MAP["protocol_num"]], errors="coerce")
    out["src_port"] = 0
    out[LABEL_COLUMN] = resolve_labels(df[CIC_LABEL_COLUMN])
    return out


def load_training_frame(path: Path) -> tuple[pd.DataFrame, str]:
    df = _clean_columns(pd.read_csv(path, low_memory=False))
    if all(feature in df.columns for feature in FEATURES):
        label_col = LABEL_COLUMN if LABEL_COLUMN in df.columns else CIC_LABEL_COLUMN
        if label_col not in df.columns:
            raise ValueError("CSV has canonical features but no label column")
        frame = df.copy()
        frame[LABEL_COLUMN] = resolve_labels(df[label_col])
        return frame, f"user_csv:{path.name}"
    return _load_cic(df), f"cic_ids2017:{path.name}"


def make_synthetic_frame(n_samples: int = 4000, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    n_attack = int(n_samples * 0.35)
    n_benign = n_samples - n_attack

    def frame_for(count: int, attack: bool) -> pd.DataFrame:
        if attack:
            duration_ms = rng.lognormal(mean=4.0, sigma=1.3, size=count)
            packets = rng.lognormal(mean=4.2, sigma=0.9, size=count)
            mean_pkt = rng.lognormal(mean=4.0, sigma=0.5, size=count)
            dst_port = rng.choice([22, 23, 3389, 80, 443, 0], size=count)
        else:
            duration_ms = rng.lognormal(mean=7.0, sigma=1.2, size=count)
            packets = 4 + rng.poisson(18, size=count)
            mean_pkt = rng.lognormal(mean=5.8, sigma=0.5, size=count)
            dst_port = rng.choice([80, 443, 53, 22, 8080, 123, 443], size=count)

        duration_s = np.maximum(duration_ms / 1000.0, 1e-3)
        byte_count = packets * mean_pkt
        return pd.DataFrame(
            {
                "duration_ms": duration_ms,
                "protocol_num": rng.choice([6, 17, 1], size=count, p=[0.65, 0.30, 0.05]),
                "src_port": rng.integers(1024, 65536, size=count),
                "dst_port": dst_port,
                "packets": packets,
                "bytes": byte_count,
                "bytes_per_s": byte_count / duration_s,
                "packets_per_s": packets / duration_s,
                "mean_pkt_size": mean_pkt,
                "min_pkt_size": np.maximum(mean_pkt * rng.uniform(0.2, 0.6, count), 40),
                "max_pkt_size": mean_pkt * rng.uniform(1.2, 2.5, count),
                "stddev_pkt_size": mean_pkt * rng.uniform(0.1, 0.8, count),
                LABEL_COLUMN: ATTACK_LABEL if attack else BENIGN_LABEL,
            }
        )

    frame = pd.concat(
        [frame_for(n_benign, False), frame_for(n_attack, True)], ignore_index=True
    )
    # Inject missing values to exercise the same imputation as in prediction.
    for feature in FEATURES:
        mask = rng.random(len(frame)) < 0.01
        frame.loc[mask, feature] = np.nan
    return frame.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, help="Training CSV (canonical or CIC-IDS2017)")
    parser.add_argument("--demo", action="store_true", help="Force synthetic demo data")
    parser.add_argument("--out", type=Path, default=Path("/data/models/model.joblib"))
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.data and not args.demo:
        frame, source = load_training_frame(args.data)
    else:
        frame = make_synthetic_frame(seed=args.seed)
        source = "synthetic_demo"

    if LABEL_COLUMN not in frame.columns or frame[LABEL_COLUMN].nunique() < 2:
        raise SystemExit("Training data must contain both benign and attack labels")

    matrix, medians = build_feature_matrix(frame)
    labels = resolve_labels(frame[LABEL_COLUMN])

    x_train, x_test, y_train, y_test = train_test_split(
        matrix, labels, test_size=0.25, random_state=args.seed, stratify=labels
    )

    classifier = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=args.seed,
        n_jobs=1,
    )
    classifier.fit(x_train, y_train)

    predictions = classifier.predict(x_test)
    accuracy = float(accuracy_score(y_test, predictions))
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": classifier,
        "features": FEATURES,
        "medians": {feature: float(value) for feature, value in medians.items()},
        "threshold": float(args.threshold),
        "data_source": source,
        "demo": source == "synthetic_demo",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "rows": int(len(frame)),
        "metrics": {"accuracy": accuracy, "classification_report": report},
    }
    joblib.dump(bundle, args.out)

    report_path = args.out.parent / "train_report.json"
    report_path.write_text(
        json.dumps(
            {
                "data_source": source,
                "demo": bundle["demo"],
                "rows": bundle["rows"],
                "accuracy": accuracy,
                "classification_report": report,
            },
            indent=2,
            default=float,
        )
    )

    print(f"[ai-engine] trained on {source} ({len(frame)} rows)")
    print(f"[ai-engine] holdout accuracy: {accuracy:.3f}")
    if bundle["demo"]:
        print("[ai-engine] WARNING: synthetic DEMO data -- not real experimental results")
    print(f"[ai-engine] model saved to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
