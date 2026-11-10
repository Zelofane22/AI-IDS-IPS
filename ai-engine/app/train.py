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
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.tree import DecisionTreeClassifier

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
    # No src_port: it is an ephemeral port, not part of the feature contract.
    out[LABEL_COLUMN] = resolve_labels(df[CIC_LABEL_COLUMN])
    out["attack_family"] = df[CIC_LABEL_COLUMN].astype(str).str.strip()
    if "Timestamp" in df.columns:
        ts = pd.to_datetime(df["Timestamp"], format="mixed", errors="coerce")
        # CIC-IDS2017 timestamps use a 12h clock without AM/PM and the capture ran
        # 09:00-17:00: hours 1-7 are afternoon (13-19h). Fix so sorting is chronological.
        out["timestamp"] = ts.where(~(ts.dt.hour < 8), ts + pd.Timedelta(hours=12))
    return out


def load_training_frame(path: Path) -> tuple[pd.DataFrame, str]:
    df = _clean_columns(pd.read_csv(path, low_memory=False, encoding_errors="replace"))
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


def split_frame(frame: pd.DataFrame, mode: str, seed: int, test_size: float = 0.25):
    """Split BEFORE any imputation. 'temporal' keeps the last part for testing."""
    labels = resolve_labels(frame[LABEL_COLUMN])
    if mode == "temporal":
        if "timestamp" in frame.columns and frame["timestamp"].notna().any():
            order = frame["timestamp"].sort_values(kind="stable").index
        else:
            print("[ai-engine] WARNING: no Timestamp column, using file order for temporal split")
            order = frame.index
        cut = int(len(order) * (1 - test_size))
        return frame.loc[order[:cut]], frame.loc[order[cut:]]
    return train_test_split(frame, test_size=test_size, random_state=seed, stratify=labels)


def _signed_log(x):
    return np.sign(x) * np.log1p(np.abs(x))


def metrics_at(y_true, proba, threshold: float) -> dict:
    y_true = np.asarray(y_true)
    pred = (np.asarray(proba) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    div = lambda a, b: float(a / b) if b else 0.0
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    out = {
        "threshold": float(threshold),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "precision": precision,
        "recall": recall,
        "f1": div(2 * precision * recall, precision + recall),
        "fpr": div(fp, fp + tn),
    }
    if len(set(y_true.tolist())) == 2:
        out["roc_auc"] = float(roc_auc_score(y_true, proba))
        out["pr_auc"] = float(average_precision_score(y_true, proba))
    return out


def _rf(seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200, max_depth=None, min_samples_leaf=2,
        class_weight="balanced", random_state=seed, n_jobs=1,
    )


def run_baselines(x_tr, y_tr, x_te, y_te, threshold, seed) -> dict:
    """Reference models for the memoire: is the Random Forest really needed?"""
    results = {}
    logreg = make_pipeline(
        FunctionTransformer(_signed_log), StandardScaler(),
        LogisticRegression(max_iter=1000, class_weight="balanced"),
    ).fit(x_tr, y_tr)
    results["logistic_regression"] = metrics_at(y_te, logreg.predict_proba(x_te)[:, 1], threshold)
    tree = DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=seed).fit(x_tr, y_tr)
    results["decision_tree_depth3"] = metrics_at(y_te, tree.predict_proba(x_te)[:, 1], threshold)
    # Shortcut check: does the RF only learn the destination port?
    cols = [c for c in x_tr.columns if c not in ("dst_port", "protocol_num")]
    rf_np = _rf(seed).fit(x_tr[cols], y_tr)
    results["rf_without_dst_port_and_protocol"] = metrics_at(
        y_te, rf_np.predict_proba(x_te[cols])[:, 1], threshold
    )
    return results


def zero_day_experiment(frame, train_df, test_df, family, threshold, seed) -> dict | None:
    """Hide one attack family from training; measure recall on it (supervised RF
    vs unsupervised IsolationForest trained on benign traffic only).

    The hidden family is never seen in training, so ALL its flows (train+test
    portions) are used for the recall; FPR is measured on the benign test flows."""
    if "attack_family" not in frame.columns:
        print("[ai-engine] --holdout-family needs a CIC-style CSV (attack_family column)")
        return None
    target = family.strip().upper()
    fam_all = frame["attack_family"].str.upper()
    if not (fam_all == target).any():
        print(f"[ai-engine] family {family!r} not found in the dataset")
        return None
    tr = train_df[train_df["attack_family"].str.upper() != target]
    hidden = frame[fam_all == target]
    benign_te = test_df[resolve_labels(test_df[LABEL_COLUMN]).values == 0]
    if tr[LABEL_COLUMN].nunique() < 2 or benign_te.empty:
        print("[ai-engine] zero-day experiment skipped: not enough classes after hiding the family")
        return None

    x_tr, medians = build_feature_matrix(tr)
    y_tr = resolve_labels(tr[LABEL_COLUMN])
    x_hid, _ = build_feature_matrix(hidden, medians)
    x_ben, _ = build_feature_matrix(benign_te, medians)

    rf = _rf(seed).fit(x_tr, y_tr)
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=seed, n_jobs=1)
    iso.fit(x_tr[y_tr.values == 0])

    rf_flag = lambda x: rf.predict_proba(x)[:, list(rf.classes_).index(ATTACK_LABEL)] >= threshold
    iso_flag = lambda x: iso.predict(x) == -1
    return {
        "hidden_family": family,
        "hidden_family_flows": int(len(hidden)),
        "benign_test_flows": int(len(benign_te)),
        "random_forest_supervised": {
            "recall_on_hidden_family": float(rf_flag(x_hid).mean()),
            "fpr_on_benign": float(rf_flag(x_ben).mean()),
        },
        "isolation_forest_benign_only": {
            "recall_on_hidden_family": float(iso_flag(x_hid).mean()),
            "fpr_on_benign": float(iso_flag(x_ben).mean()),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, help="Training CSV (canonical or CIC-IDS2017)")
    parser.add_argument("--demo", action="store_true", help="Force synthetic demo data")
    parser.add_argument("--out", type=Path, default=Path("/data/models/model.joblib"))
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--split", choices=["auto", "random", "temporal"], default="auto",
                        help="auto = temporal for --data, random for --demo")
    parser.add_argument("--holdout-family", default=None,
                        help="CIC attack label to hide from training (zero-day experiment)")
    args = parser.parse_args()

    if args.data and not args.demo:
        frame, source = load_training_frame(args.data)
    else:
        frame = make_synthetic_frame(seed=args.seed)
        source = "synthetic_demo"

    if LABEL_COLUMN not in frame.columns or frame[LABEL_COLUMN].nunique() < 2:
        raise SystemExit("Training data must contain both benign and attack labels")

    split_mode = args.split if args.split != "auto" else ("temporal" if source != "synthetic_demo" else "random")
    train_df, test_df = split_frame(frame, split_mode, args.seed)
    y_train = resolve_labels(train_df[LABEL_COLUMN])
    y_test = resolve_labels(test_df[LABEL_COLUMN])
    if y_train.nunique() < 2 or y_test.nunique() < 2:
        raise SystemExit(
            f"{split_mode} split leaves a single class in train or test; "
            "use a CSV covering benign+attack over time, or --split random"
        )

    # Imputation medians come from the TRAIN split only (no test leakage).
    x_train, medians = build_feature_matrix(train_df)
    x_test, _ = build_feature_matrix(test_df, medians)

    classifier = _rf(args.seed)
    classifier.fit(x_train, y_train)

    proba = classifier.predict_proba(x_test)[:, list(classifier.classes_).index(ATTACK_LABEL)]
    predictions = (proba >= args.threshold).astype(int)
    accuracy = float(accuracy_score(y_test, predictions))
    report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    evaluation = {
        "split": split_mode,
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "random_forest": metrics_at(y_test, proba, args.threshold),
        "baselines": run_baselines(x_train, y_train, x_test, y_test, args.threshold, args.seed),
        "feature_importance": dict(sorted(
            ((f, float(v)) for f, v in zip(FEATURES, classifier.feature_importances_)),
            key=lambda kv: -kv[1])),
    }
    if args.holdout_family:
        evaluation["zero_day"] = zero_day_experiment(
            frame, train_df, test_df, args.holdout_family, args.threshold, args.seed)

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
        "metrics": {"accuracy": accuracy, "classification_report": report, "evaluation": evaluation},
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
                "evaluation": evaluation,
            },
            indent=2,
            default=float,
        )
    )

    print(f"[ai-engine] trained on {source} ({len(frame)} rows)")
    rf_m = evaluation["random_forest"]
    print(f"[ai-engine] split={split_mode} train={len(train_df)} test={len(test_df)}")
    print(f"[ai-engine] holdout accuracy: {accuracy:.3f}")
    print(f"[ai-engine] recall={rf_m['recall']:.3f} fpr={rf_m['fpr']:.4f} "
          f"f1={rf_m['f1']:.3f} auc={rf_m.get('roc_auc', float('nan')):.3f}")
    if bundle["demo"]:
        print("[ai-engine] WARNING: synthetic DEMO data -- not real experimental results")
    print(f"[ai-engine] model saved to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
