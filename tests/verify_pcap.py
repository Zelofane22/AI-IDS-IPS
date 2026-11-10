#!/usr/bin/env python3
"""Validate the synthetic demo PCAP structure without external dependencies."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "pcap",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "data" / "pcaps" / "synthetic_demo.pcap",
    )
    args = parser.parse_args()

    data = args.pcap.read_bytes()
    if len(data) < 24:
        raise SystemExit("file too small to be a pcap")

    magic, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHIIII", data[:24])
    if magic != 0xA1B2C3D4 or linktype != 1:
        raise SystemExit(f"unexpected pcap header magic={magic:#x} linktype={linktype}")

    offset = 24
    packets = 0
    while offset + 16 <= len(data):
        _, _, captured, _ = struct.unpack("<IIII", data[offset : offset + 16])
        offset += 16 + captured
        packets += 1

    if offset != len(data):
        raise SystemExit("truncated or malformed packet records")
    if packets == 0:
        raise SystemExit("pcap contains no packets")

    print(
        f"OK: {args.pcap} version={major}.{minor} snaplen={snaplen} packets={packets}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
