#!/usr/bin/env python3
"""Build a small deterministic CIC-IDS2017 training sample (stdlib only).

Reads the three Friday CSV files (Morning, Afternoon-PortScan, Afternoon-DDos)
from data/cic/raw/, concatenates them in that order, then keeps one row out of
every k (k chosen so the result is <= 150 000 rows) while preserving order.

Output: data/cic/train.csv (UTF-8).
"""

from __future__ import annotations

import csv
import math
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "cic" / "raw"
OUT_PATH = ROOT / "data" / "cic" / "train.csv"

FILES = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

REQUIRED_COLUMNS = [
    "Destination Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Std",
    "Timestamp",
    "Label",
]

MAX_ROWS = 150_000
MIN_FAMILY_ROWS = 200


def _open(path: Path):
    return path.open(encoding="utf-8", errors="replace", newline="")


def _header(reader: csv.reader) -> tuple[list[str], list[str]]:
    raw = next(reader)
    stripped = [c.strip().lstrip("\ufeff") for c in raw]
    return raw, stripped


def scan(path: Path) -> dict:
    """First pass: count rows/labels and record raw timestamp extrema."""
    with _open(path) as handle:
        reader = csv.reader(handle)
        _, header = _header(reader)
        try:
            ts_idx = header.index("Timestamp")
            label_idx = header.index("Label")
        except ValueError as exc:
            raise SystemExit(f"{path.name}: missing column ({exc})")
        labels: Counter = Counter()
        rows = 0
        ts_min = None
        ts_max = None
        for row in reader:
            if len(row) != len(header):
                continue
            rows += 1
            labels[row[label_idx].strip()] += 1
            ts = row[ts_idx].strip()
            if ts:
                if ts_min is None or ts < ts_min:
                    ts_min = ts
                if ts_max is None or ts > ts_max:
                    ts_max = ts
    return {"rows": rows, "labels": labels, "ts_min": ts_min, "ts_max": ts_max}


def ensure_columns(path: Path) -> list[str]:
    with _open(path) as handle:
        reader = csv.reader(handle)
        raw, header = _header(reader)
    missing = [c for c in REQUIRED_COLUMNS if c not in header]
    if missing:
        raise SystemExit(f"{path.name}: missing required columns: {missing}")
    return raw


def main() -> int:
    for name in FILES:
        path = RAW_DIR / name
        if not path.is_file():
            raise SystemExit(f"missing input file: {path}")
        ensure_columns(path)

    scans = {name: scan(RAW_DIR / name) for name in FILES}
    total_rows = sum(scans[name]["rows"] for name in FILES)
    total_labels: Counter = Counter()
    for name in FILES:
        total_labels.update(scans[name]["labels"])

    print(f"Rows before sampling: {total_rows}")
    print("Label counts before sampling:")
    for label, count in sorted(total_labels.items()):
        print(f"  {label}: {count}")
    print("Raw Timestamp min/max per file:")
    for name in FILES:
        info = scans[name]
        print(f"  {name}: min={info['ts_min']} max={info['ts_max']}")

    if total_rows == 0:
        raise SystemExit("no rows read from the input files")

    k = max(1, math.ceil(total_rows / MAX_ROWS))
    # If a rare family would drop below the floor, try smaller k values that
    # still respect the global cap (only possible if k > 1 and the cap allows).
    while k > 1:
        projected = {
            label: math.ceil(count / k) for label, count in total_labels.items()
        }
        if all(count >= MIN_FAMILY_ROWS or count == 0 for count in projected.values()):
            break
        k -= 1
    print(f"Sampling step k = {k} (1 row out of {k})")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    index = 0
    written = 0
    after_labels: Counter = Counter()
    with OUT_PATH.open("w", encoding="utf-8", newline="") as out:
        writer = csv.writer(out)
        first_header_written = False
        for name in FILES:
            with _open(RAW_DIR / name) as handle:
                reader = csv.reader(handle)
                raw, header = _header(reader)
                if not first_header_written:
                    writer.writerow(header)
                    first_header_written = True
                label_idx = header.index("Label")
                for row in reader:
                    if len(row) != len(header):
                        continue
                    if index % k == 0:
                        writer.writerow(row)
                        after_labels[row[label_idx].strip()] += 1
                        written += 1
                    index += 1

    print(f"Rows after sampling: {written} (written to {OUT_PATH})")
    print("Label counts after sampling:")
    for label, count in sorted(after_labels.items()):
        print(f"  {label}: {count}")

    dropped = [
        label
        for label, count in after_labels.items()
        if count and count < MIN_FAMILY_ROWS
    ]
    if dropped:
        print(f"WARNING: families below {MIN_FAMILY_ROWS} rows: {dropped}")
    if written > MAX_ROWS:
        raise SystemExit(f"BUG: wrote {written} rows, above the {MAX_ROWS} cap")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
