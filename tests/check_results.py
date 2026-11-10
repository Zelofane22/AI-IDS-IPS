#!/usr/bin/env python3
"""Check that results/nfstream_temporal.json is internally consistent (stdlib only).

* confusion-matrix sum == test_rows;
* precision, recall, F1 and FPR recomputed from the matrix == stored values (1e-9).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOL = 1e-9


def check_block(name: str, block: dict, test_rows: int, errors: list[str]) -> None:
    cm = block["confusion_matrix"]
    tn, fp, fn, tp = cm["tn"], cm["fp"], cm["fn"], cm["tp"]
    if tn + fp + fn + tp != test_rows:
        errors.append(f"{name}: matrix sum {tn + fp + fn + tp} != test_rows {test_rows}")
    div = lambda a, b: a / b if b else 0.0
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    expected = {
        "precision": precision,
        "recall": recall,
        "f1": div(2 * precision * recall, precision + recall),
        "fpr": div(fp, fp + tn),
    }
    for key, value in expected.items():
        if abs(block[key] - value) > TOL:
            errors.append(f"{name}: {key} stored {block[key]!r} != recomputed {value!r}")
    print(f"  {name}: tn={tn} fp={fp} fn={fn} tp={tp} sum={tn + fp + fn + tp} "
          + " ".join(f"{k}={v:.6f}" for k, v in expected.items()))


def main() -> int:
    path = ROOT / "results" / "nfstream_temporal.json"
    evaluation = json.loads(path.read_text())["evaluation"]
    test_rows = evaluation["test_rows"]
    errors: list[str] = []
    print(f"{path.relative_to(ROOT)}: split={evaluation['split']} "
          f"train_rows={evaluation['train_rows']} test_rows={test_rows}")
    check_block("random_forest", evaluation["random_forest"], test_rows, errors)
    for name, block in evaluation.get("baselines", {}).items():
        check_block(f"baselines.{name}", block, test_rows, errors)
    if errors:
        print("FAILED:", *errors, sep="\n  - ")
        return 1
    print("OK: matrices sum to test_rows; precision/recall/F1/FPR match (tol 1e-9)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
