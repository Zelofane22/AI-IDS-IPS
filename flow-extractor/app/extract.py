"""Extract normalized flow features from PCAP files with NFStream.

Output CSV is consumed by the ai-engine and the dashboard. Flow identity
columns are kept alongside the statistical features so that events can later be
correlated with Suricata alerts on real shared keys (5-tuple).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from nfstream import NFStreamer

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

IDENTITY_COLUMNS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
]

FEATURE_COLUMNS = [
    "protocol_num",
    "duration_ms",
    "packets",
    "bytes",
    "bytes_per_s",
    "packets_per_s",
    "mean_pkt_size",
    "min_pkt_size",
    "max_pkt_size",
    "stddev_pkt_size",
]

OUTPUT_COLUMNS = IDENTITY_COLUMNS + FEATURE_COLUMNS + [
    "first_seen_ms",
    "application_name",
]


def find_pcaps(path: Path) -> list[Path]:
    if path.is_dir():
        files = sorted(path.glob("*.pcap")) + sorted(path.glob("*.pcapng"))
    elif path.is_file():
        files = [path]
    else:
        files = []
    return [f for f in files if f.is_file()]


def _series(df: pd.DataFrame, *names: str, default: float = np.nan) -> pd.Series:
    for name in names:
        if name in df.columns:
            return pd.to_numeric(df[name], errors="coerce")
    return pd.Series([default] * len(df), index=df.index, dtype="float64")


def _string_series(df: pd.DataFrame, name: str, default: str = "") -> pd.Series:
    if name in df.columns:
        return df[name].fillna(default).astype(str)
    return pd.Series([default] * len(df), index=df.index, dtype="object")


def _safe_rate(numerator: pd.Series, duration_ms: pd.Series) -> pd.Series:
    seconds = duration_ms / 1000.0
    rate = numerator / seconds.replace(0, np.nan)
    return rate.replace([np.inf, -np.inf], np.nan)


def normalize(raw: pd.DataFrame, source_file: str) -> pd.DataFrame:
    if raw.empty:
        return pd.DataFrame(columns=OUTPUT_COLUMNS)

    df = pd.DataFrame(index=raw.index)

    raw_id = raw["id"] if "id" in raw.columns else pd.Series(range(len(raw)), index=raw.index)
    df["flow_id"] = source_file + ":" + raw_id.astype(str)

    df["src_ip"] = _string_series(raw, "src_ip", "0.0.0.0")
    df["dst_ip"] = _string_series(raw, "dst_ip", "0.0.0.0")
    df["src_port"] = _series(raw, "src_port", default=0).fillna(0).astype(int)
    df["dst_port"] = _series(raw, "dst_port", default=0).fillna(0).astype(int)

    protocol_num = _series(raw, "protocol", default=0).fillna(0).astype(int)
    df["protocol_num"] = protocol_num
    df["protocol"] = protocol_num.map(PROTOCOL_NAMES).fillna("OTHER")

    df["duration_ms"] = _series(
        raw, "bidirectional_duration_ms"
    ).fillna(0.0)

    packets = _series(raw, "bidirectional_packets")
    if packets.isna().all():
        packets = _series(raw, "src2dst_packets", default=0).fillna(0) + _series(
            raw, "dst2src_packets", default=0
        ).fillna(0)
    df["packets"] = packets.fillna(0)

    byte_count = _series(raw, "bidirectional_bytes")
    if byte_count.isna().all():
        byte_count = _series(raw, "src2dst_bytes", default=0).fillna(0) + _series(
            raw, "dst2src_bytes", default=0
        ).fillna(0)
    df["bytes"] = byte_count.fillna(0)

    df["bytes_per_s"] = _safe_rate(df["bytes"], df["duration_ms"]).fillna(0.0)
    df["packets_per_s"] = _safe_rate(df["packets"], df["duration_ms"]).fillna(0.0)

    df["mean_pkt_size"] = _series(raw, "bidirectional_mean_ps").fillna(0.0)
    df["min_pkt_size"] = _series(raw, "bidirectional_min_ps").fillna(0.0)
    df["max_pkt_size"] = _series(raw, "bidirectional_max_ps").fillna(0.0)
    df["stddev_pkt_size"] = _series(raw, "bidirectional_stddev_ps").fillna(0.0)

    df["first_seen_ms"] = _series(raw, "bidirectional_first_seen_ms").fillna(0)
    df["application_name"] = _string_series(raw, "application_name", "")

    return df[OUTPUT_COLUMNS]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", default="/data/pcaps", help="PCAP file or directory")
    parser.add_argument("--out", default="/data/flows/flows.csv", help="Output CSV")
    parser.add_argument("--idle-timeout", type=int, default=120)
    parser.add_argument("--active-timeout", type=int, default=1800)
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    pcaps = find_pcaps(pcap_path)
    if not pcaps:
        print(f"[flow-extractor] no PCAP found at {pcap_path}", file=sys.stderr)
        pd.DataFrame(columns=OUTPUT_COLUMNS).to_csv(out_path, index=False)
        print(f"[flow-extractor] wrote empty CSV to {out_path}")
        return 0

    frames: list[pd.DataFrame] = []
    for pcap in pcaps:
        print(f"[flow-extractor] reading {pcap}")
        streamer = NFStreamer(
            source=str(pcap),
            statistical_analysis=True,
            idle_timeout=args.idle_timeout,
            active_timeout=args.active_timeout,
        )
        raw = streamer.to_pandas()
        frames.append(normalize(raw, pcap.stem))
        print(f"[flow-extractor]   {len(raw)} flow(s)")

    combined = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    combined = combined.sort_values("flow_id").reset_index(drop=True)
    combined.to_csv(out_path, index=False)
    print(f"[flow-extractor] wrote {len(combined)} flow(s) to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
