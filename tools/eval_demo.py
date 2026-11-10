#!/usr/bin/env python3
"""Score the pipeline on the REAL demo extract (stdlib only).

Joins predictions.json (AI) and logs/eve.json (Suricata) with the ground-truth
labels of the extract flows (built by tools/label_nfstream_flows.py from the
CIC CSVs) on flow_id / 5-tuple only. The extract windows were excluded from
training, so these are unseen flows (same day and same attack campaigns, though).

Usage:
    python3 tools/eval_demo.py --labels data/cic/demo_labels.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--labels", type=Path, default=ROOT / "data/cic/demo_labels.csv")
    parser.add_argument("--predictions", type=Path, default=ROOT / "data/predictions/predictions.json")
    parser.add_argument("--eve", type=Path, default=ROOT / "logs/eve.json")
    parser.add_argument("--out", type=Path, default=ROOT / "results/demo_extract_eval.json")
    args = parser.parse_args()

    labels = {row["flow_id"]: row["attack_family"] for row in csv.DictReader(args.labels.open())}
    payload = json.loads(args.predictions.read_text())
    preds = {p["flow_id"]: p for p in payload["predictions"] if p["flow_id"] in labels}

    alert_keys = set()
    with args.eve.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = json.loads(line) if line.strip() else {}
            if event.get("event_type") == "alert":
                alert_keys.add((event.get("src_ip"), event.get("dest_ip"), event.get("src_port"),
                                event.get("dest_port"), str(event.get("proto", "")).upper()))

    per_family: dict[str, Counter] = defaultdict(Counter)
    for flow_id, pred in preds.items():
        family = labels[flow_id]
        key = (pred["src_ip"], pred["dst_ip"], pred["src_port"], pred["dst_port"], pred["protocol"])
        ai = bool(pred["is_attack"])
        ids = key in alert_keys
        c = per_family[family]
        c["flows"] += 1
        c["ai"] += ai
        c["suricata"] += ids
        c["either"] += ai or ids
        c["both"] += ai and ids

    report = {"threshold": payload.get("threshold"), "data_source": payload.get("data_source"),
              "labelled_flows": len(preds), "per_family": {}}
    print(f"{'family':<10}{'flows':>8}{'AI':>8}{'Suricata':>10}{'either':>8}{'both':>8}  (share flagged)")
    for family, c in sorted(per_family.items()):
        n = c["flows"]
        rates = {k: c[k] / n for k in ("ai", "suricata", "either", "both")}
        report["per_family"][family] = {"flows": n, **{f"{k}_rate": v for k, v in rates.items()}}
        print(f"{family:<10}{n:>8}" + "".join(f"{rates[k]:>{w}.3f}" for k, w in
                                              (("ai", 8), ("suricata", 10), ("either", 8), ("both", 8))))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))
    print(f"written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
