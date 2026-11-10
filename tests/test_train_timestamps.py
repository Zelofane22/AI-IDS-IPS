#!/usr/bin/env python3
"""Regression test: the temporal split must parse every canonical timestamp.

Before the fix, pandas inferred the timestamp format from the first row
("...:50.315000+00:00") and turned whole-second values ("...:17+00:00") into
NaT; the temporal split sorted them last, moving early flows into the test set.

Needs pandas/scikit-learn: run inside the ai-engine image, e.g.
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL \
    --security-opt no-new-privileges -e HOME=/tmp -v "$PWD/tests:/tests:ro" \
    --entrypoint python ai-ids-ips-ai-engine /tests/test_train_timestamps.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/app/app")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ai-engine" / "app"))

import pandas as pd  # noqa: E402

from features import FEATURES  # noqa: E402
from train import load_training_frame, split_frame  # noqa: E402


def main() -> int:
    # 8 rows in chronological order; rows 1 and 3 have whole-second timestamps.
    stamps = [
        "2017-07-07 11:59:50.315000+00:00",
        "2017-07-07 12:16:17+00:00",
        "2017-07-07 12:30:00.100000+00:00",
        "2017-07-07 12:46:49+00:00",
        "2017-07-07 13:00:00.500000+00:00",
        "2017-07-07 14:00:00.500000+00:00",
        "2017-07-07 15:00:00.500000+00:00",
        "2017-07-07 16:00:00.500000+00:00",
    ]
    df = pd.DataFrame({f: [1.0] * len(stamps) for f in FEATURES})
    df["timestamp"] = stamps
    df["label"] = [0, 0, 1, 0, 1, 0, 1, 1]
    df["attack_family"] = ["BENIGN", "BENIGN", "PortScan", "BENIGN", "PortScan", "BENIGN", "DDoS", "DDoS"]

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "canonical.csv"
        df.to_csv(path, index=False)
        frame, source = load_training_frame(path)

    failures = []
    nat = int(frame["timestamp"].isna().sum())
    if nat:
        failures.append(f"{nat} timestamp(s) parsed as NaT")
    train, test = split_frame(frame, "temporal", 42)
    if sorted(test.index) != [6, 7]:
        failures.append(f"temporal test rows should be the 2 latest [6, 7], got {sorted(test.index)}")
    if not source.startswith("nfstream_csv:"):
        failures.append(f"unexpected source {source}")

    if failures:
        print("FAILED:", *failures, sep="\n  - ")
        return 1
    print("OK: all timestamps parsed; temporal test = latest rows only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
