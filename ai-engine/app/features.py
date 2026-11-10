"""Canonical feature contract shared by train and predict.

Both scripts MUST build their matrices through :func:`build_feature_matrix` so
that feature order and missing-value handling can never drift apart.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

IDENTITY_COLUMNS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
]

FEATURES = [
    "duration_ms",
    "protocol_num",
    "src_port",
    "dst_port",
    "packets",
    "bytes",
    "bytes_per_s",
    "packets_per_s",
    "mean_pkt_size",
    "min_pkt_size",
    "max_pkt_size",
    "stddev_pkt_size",
]

LABEL_COLUMN = "label"
ATTACK_LABEL = 1
BENIGN_LABEL = 0

# Label as seen in the public CIC-IDS2017 CSV files.
CIC_LABEL_COLUMN = "Label"


def resolve_labels(series: pd.Series) -> pd.Series:
    """Map a label column to 0 (benign) / 1 (attack)."""
    numeric = pd.to_numeric(series, errors="coerce")
    if numeric.notna().all():
        return (numeric > 0).astype(int)
    return (
        series.astype(str).str.strip().str.upper().eq("BENIGN").map(
            {True: BENIGN_LABEL, False: ATTACK_LABEL}
        )
    ).astype(int)


def build_feature_matrix(
    df: pd.DataFrame, medians: pd.Series | None = None
) -> tuple[pd.DataFrame, pd.Series]:
    """Return the model matrix plus the medians used for imputation.

    Missing columns become NaN then are filled with medians. When ``medians`` is
    None it is computed from ``df`` (training path); otherwise the exact medians
    stored with the model are reused (prediction path).
    """
    matrix = pd.DataFrame(index=df.index)
    for feature in FEATURES:
        if feature in df.columns:
            values = pd.to_numeric(df[feature], errors="coerce")
        else:
            values = pd.Series(np.nan, index=df.index, dtype="float64")
        matrix[feature] = values.replace([np.inf, -np.inf], np.nan)

    if medians is None:
        medians = matrix.median(numeric_only=True)

    medians = pd.Series(medians).reindex(FEATURES).astype("float64").fillna(0.0)
    matrix = matrix.fillna(medians)
    return matrix, medians
