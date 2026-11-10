"""Run the trained Random Forest over the normalized flow CSV.

Predictions are written as JSON (atomic replace) so the dashboard never reads a
half-written file. Every prediction keeps the flow identity columns needed for
correlation with Suricata alerts.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from features import ATTACK_LABEL, FEATURES, IDENTITY_COLUMNS, build_feature_matrix


def _python_scalar(value):
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    return value


def _records(df: pd.DataFrame, probabilities: np.ndarray, threshold: float) -> list[dict]:
    records: list[dict] = []
    for index, probability in zip(df.index, probabilities):
        row = df.loc[index]
        probability = float(probability)
        record = {
            "flow_id": str(row.get("flow_id", "")),
            "src_ip": str(row.get("src_ip", "")),
            "dst_ip": str(row.get("dst_ip", "")),
            "src_port": _python_scalar(row.get("src_port", 0)),
            "dst_port": _python_scalar(row.get("dst_port", 0)),
            "protocol": str(row.get("protocol", "")),
            "label": "suspicious" if probability >= threshold else "benign",
            "attack_probability": round(probability, 6),
            "is_attack": bool(probability >= threshold),
        }
        records.append(record)
    return records


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2))
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", type=Path, default=Path("/data/flows/flows.csv"))
    parser.add_argument("--model", type=Path, default=Path("/data/models/model.joblib"))
    parser.add_argument("--out", type=Path, default=Path("/data/predictions/predictions.json"))
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--allow-empty", action="store_true")
    args = parser.parse_args()

    if not args.model.is_file():
        raise SystemExit(f"model not found: {args.model}")

    bundle = joblib.load(args.model)
    threshold = float(args.threshold if args.threshold is not None else bundle["threshold"])
    features = bundle.get("features", FEATURES)
    if list(features) != list(FEATURES):
        raise SystemExit("model feature contract differs from features.py; retrain the model")
    medians = pd.Series(bundle["medians"])

    if not args.flows.is_file():
        if not args.allow_empty:
            raise SystemExit(f"flow CSV not found: {args.flows}")
        write_json_atomic(
            args.out,
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "model": str(args.model),
                "data_source": bundle.get("data_source"),
                "demo": bundle.get("demo", False),
                "threshold": threshold,
                "flow_count": 0,
                "suspicious_count": 0,
                "predictions": [],
            },
        )
        print(f"[ai-engine] no flows; wrote empty predictions to {args.out}")
        return 0

    flows = pd.read_csv(args.flows, low_memory=False)
    if flows.empty:
        probabilities = np.array([], dtype=float)
        records: list[dict] = []
    else:
        matrix, _ = build_feature_matrix(flows, medians=medians)
        classes = list(bundle["model"].classes_)
        attack_index = classes.index(ATTACK_LABEL)
        probabilities = bundle["model"].predict_proba(matrix)[:, attack_index]
        records = _records(flows, probabilities, threshold)

    suspicious = sum(1 for record in records if record["is_attack"])
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": str(args.model),
        "data_source": bundle.get("data_source"),
        "demo": bool(bundle.get("demo", False)),
        "threshold": threshold,
        "flow_count": len(records),
        "suspicious_count": suspicious,
        "predictions": records,
    }
    write_json_atomic(args.out, payload)
    print(
        f"[ai-engine] classified {len(records)} flow(s), {suspicious} suspicious "
        f"(threshold={threshold}); written to {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
