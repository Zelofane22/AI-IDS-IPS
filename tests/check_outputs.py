#!/usr/bin/env python3
"""Validate the artifacts produced by a full docker compose run (stdlib only)."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FLOW_COLUMNS = {
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
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
}


def main() -> int:
    errors: list[str] = []
    notes: list[str] = []

    pcaps = list((ROOT / "data" / "pcaps").glob("*.pcap"))
    if not pcaps:
        errors.append("no .pcap file in data/pcaps")
    else:
        notes.append(f"{len(pcaps)} pcap file(s)")

    eve = ROOT / "logs" / "eve.json"
    alerts = 0
    event_types: dict[str, int] = {}
    if not eve.is_file():
        errors.append("logs/eve.json missing")
    else:
        with eve.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    errors.append("eve.json contains an invalid JSON line")
                    break
                event_type = event.get("event_type", "unknown")
                event_types[event_type] = event_types.get(event_type, 0) + 1
                if event_type == "alert":
                    alerts += 1
        notes.append(f"eve.json events={event_types}, alerts={alerts}")

    flows_path = ROOT / "data" / "flows" / "flows.csv"
    flow_rows = 0
    if not flows_path.is_file():
        errors.append("data/flows/flows.csv missing")
    else:
        with flows_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            header = set(reader.fieldnames or [])
            missing = REQUIRED_FLOW_COLUMNS - header
            if missing:
                errors.append(f"flows.csv missing columns: {sorted(missing)}")
            flow_rows = sum(1 for _ in reader)
        if flow_rows == 0:
            errors.append("flows.csv has no flow rows")
        notes.append(f"flows.csv rows={flow_rows}")

    model = ROOT / "data" / "models" / "model.joblib"
    if not model.is_file():
        errors.append("data/models/model.joblib missing")
    else:
        notes.append(f"model size={model.stat().st_size} bytes")

    predictions_path = ROOT / "data" / "predictions" / "predictions.json"
    if not predictions_path.is_file():
        errors.append("data/predictions/predictions.json missing")
    else:
        try:
            payload = json.loads(predictions_path.read_text())
        except json.JSONDecodeError as exc:
            errors.append(f"predictions.json invalid: {exc}")
            payload = {}
        predictions = payload.get("predictions", [])
        if payload.get("flow_count") != len(predictions):
            errors.append("predictions.json flow_count does not match predictions length")
        if flow_rows and len(predictions) != flow_rows:
            errors.append(
                f"prediction count ({len(predictions)}) != flow rows ({flow_rows})"
            )
        for record in predictions[:1]:
            for field in ("flow_id", "src_ip", "dst_ip", "protocol", "label", "attack_probability"):
                if field not in record:
                    errors.append(f"prediction record missing {field}")
        notes.append(
            f"predictions={len(predictions)} suspicious={payload.get('suspicious_count')} "
            f"data_source={payload.get('data_source')}"
        )
        if payload.get("demo"):
            notes.append("predictions flagged as synthetic DEMO data")

    print("Artifact check")
    for note in notes:
        print(f"  - {note}")
    if errors:
        print("FAILED:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("OK: all required artifacts are present and coherent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
