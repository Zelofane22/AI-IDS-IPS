#!/usr/bin/env python3
"""Label NFStream flows with the CIC-IDS2017 ground truth (needs pandas).

Why: the model used to be trained on CICFlowMeter features but applied to
NFStream features (different flow timeouts, durations, directions). Training
directly on NFStream flows removes that train/predict mismatch.

How (real shared keys only, no guessing):
  * key  = unordered 5-tuple (endpoint A, endpoint B, protocol), so flow
           direction differences between the two tools do not matter;
  * time = the CIC flow start (minute resolution, local ADT = UTC-3, 12 h clock
           without AM/PM) must fall inside the NFStream flow span +/- tolerance.
A flow whose matches are all BENIGN is benign; all the same attack -> that
attack; no match -> dropped ("unmatched"). Exactly one attack family + BENIGN
-> that attack by default (--mixed-policy attack): CICFlowMeter splits a TCP
connection on FIN and labels the teardown fragment BENIGN (known CIC-IDS2017
artifact, Engelen et al. 2021), so the NFStream flow does carry attack traffic.
Several attack families -> always dropped ("conflict").

Run inside the ai-engine image, e.g.:
  docker run --rm --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp \
    --cap-drop ALL --security-opt no-new-privileges --memory 6g \
    -v "$PWD/tools:/tools:ro" -v "$PWD/data/cic:/data/cic" \
    --entrypoint python ai-ids-ips-ai-engine /tools/label_nfstream_flows.py
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

CIC_FILES = [
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
CIC_UTC_OFFSET = pd.Timedelta(hours=3)  # ADT (UTC-3) -> UTC
KEEP_COLUMNS = [
    "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "protocol_num", "duration_ms", "packets", "bytes", "bytes_per_s",
    "packets_per_s", "mean_pkt_size", "min_pkt_size", "max_pkt_size",
    "stddev_pkt_size", "first_seen_ms", "last_seen_ms",
]


def endpoint_key(ip_a, port_a, ip_b, port_b, proto) -> pd.Series:
    a = ip_a.astype(str) + ":" + port_a.astype("int64").astype(str)
    b = ip_b.astype(str) + ":" + port_b.astype("int64").astype(str)
    low = a.where(a <= b, b)
    high = b.where(a <= b, a)
    return low + "|" + high + "|" + proto.astype("int64").astype(str)


def load_cic(raw_dir: Path) -> pd.DataFrame:
    cols = ["Source IP", "Source Port", "Destination IP", "Destination Port",
            "Protocol", "Timestamp", "Label"]
    frames = []
    for name in CIC_FILES:
        df = pd.read_csv(raw_dir / name, encoding_errors="replace", low_memory=False)
        df = df.rename(columns=lambda c: str(c).lstrip("﻿").strip())[cols].dropna()
        frames.append(df)
    cic = pd.concat(frames, ignore_index=True)
    ts = pd.to_datetime(cic["Timestamp"], format="mixed", errors="coerce")
    # 12 h clock without AM/PM, capture ran 09:00-17:00: hours 1-7 are afternoon.
    ts = ts.where(~(ts.dt.hour < 8), ts + pd.Timedelta(hours=12))
    utc_ms = ((ts + CIC_UTC_OFFSET) - pd.Timestamp("1970-01-01")) // pd.Timedelta(milliseconds=1)
    out = pd.DataFrame({
        "key": endpoint_key(cic["Source IP"], pd.to_numeric(cic["Source Port"]),
                            cic["Destination IP"], pd.to_numeric(cic["Destination Port"]),
                            pd.to_numeric(cic["Protocol"])),
        "cic_start_ms": utc_ms,
        "cic_label": cic["Label"].astype(str).str.strip(),
    }).dropna()
    return out


def parse_window(value: tuple[str, str]) -> tuple[int, int]:
    def ms(v: str) -> int:
        parsed = datetime.fromisoformat(v)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    return ms(value[0]), ms(value[1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--flows", type=Path, default=Path("/data/cic/friday_nfstream_flows.csv"))
    parser.add_argument("--cic-dir", type=Path, default=Path("/data/cic/raw"))
    parser.add_argument("--out", type=Path, default=Path("/data/cic/train_nfstream.csv"))
    parser.add_argument("--tolerance-s", type=float, default=60.0,
                        help="slack around the NFStream span (CIC timestamps are minute-truncated)")
    parser.add_argument("--exclude-window", nargs=2, action="append", default=[],
                        metavar=("START", "END"),
                        help="UTC ISO window removed from the dataset (e.g. the demo extract); repeatable")
    parser.add_argument("--mixed-policy", choices=["attack", "drop"], default="attack",
                        help="one attack family + BENIGN: label as that attack, or drop the flow")
    parser.add_argument("--max-rows", type=int, default=150_000,
                        help="systematic 1-in-k sampling in time order to stay under this size")
    args = parser.parse_args()

    flows = pd.read_csv(args.flows, low_memory=False)
    flows = flows[KEEP_COLUMNS].copy()
    flows["row"] = np.arange(len(flows))
    flows["key"] = endpoint_key(flows["src_ip"], flows["src_port"], flows["dst_ip"],
                                flows["dst_port"], flows["protocol_num"])
    print(f"[label] {len(flows)} NFStream flows")

    excluded = 0
    for window in args.exclude_window:
        start, end = parse_window(window)
        overlap = (flows["first_seen_ms"] < end) & (flows["last_seen_ms"] >= start)
        excluded += int(overlap.sum())
        flows = flows[~overlap]
    if args.exclude_window:
        print(f"[label] excluded {excluded} flows overlapping {len(args.exclude_window)} window(s)")

    cic = load_cic(args.cic_dir)
    print(f"[label] {len(cic)} CIC flows; labels: {cic['cic_label'].value_counts().to_dict()}")

    tol = int(args.tolerance_s * 1000)
    merged = flows[["row", "key", "first_seen_ms", "last_seen_ms"]].merge(cic, on="key", how="inner")
    in_span = (merged["cic_start_ms"] >= merged["first_seen_ms"] - tol) & (
        merged["cic_start_ms"] <= merged["last_seen_ms"] + tol)
    merged = merged[in_span]
    per_flow = merged.groupby("row")["cic_label"].agg(lambda s: sorted(set(s)))

    flows = flows.set_index("row")
    flows["labels"] = per_flow.reindex(flows.index)
    unmatched = flows["labels"].isna()
    attacks_of = lambda v: [x for x in v if x.upper() != "BENIGN"] if isinstance(v, list) else []
    mixed = flows["labels"].map(
        lambda v: isinstance(v, list) and len(v) == 2 and len(attacks_of(v)) == 1)
    if args.mixed_policy == "attack":
        flows.loc[mixed, "labels"] = flows.loc[mixed, "labels"].map(lambda v: attacks_of(v))
    conflict = flows["labels"].map(lambda v: isinstance(v, list) and len(v) > 1)
    labelled = flows[~unmatched & ~conflict].copy()
    labelled["attack_family"] = labelled["labels"].map(lambda v: v[0])
    labelled["label"] = (labelled["attack_family"].str.upper() != "BENIGN").astype(int)
    labelled["timestamp"] = pd.to_datetime(labelled["first_seen_ms"], unit="ms", utc=True)
    labelled = labelled.drop(columns=["labels", "key"]).sort_values("first_seen_ms")

    stats = {
        "nfstream_flows": int(len(flows) + excluded),
        "excluded_demo_windows": excluded,
        "unmatched_dropped": int(unmatched.sum()),
        "mixed_benign_attack": int(mixed.sum()),
        "mixed_policy": args.mixed_policy,
        "conflict_dropped": int(conflict.sum()),
        "labelled": int(len(labelled)),
        "families_before_sampling": labelled["attack_family"].value_counts().to_dict(),
        "tolerance_s": args.tolerance_s,
    }

    k = max(1, int(np.ceil(len(labelled) / args.max_rows)))
    sample = labelled.iloc[::k]
    stats["sampling_k"] = k
    stats["rows_written"] = int(len(sample))
    stats["families_after_sampling"] = sample["attack_family"].value_counts().to_dict()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    sample.to_csv(args.out, index=False)
    args.out.with_suffix(".stats.json").write_text(json.dumps(stats, indent=2))
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
