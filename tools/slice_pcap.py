#!/usr/bin/env python3
"""Cut time windows out of a large pcap/pcapng capture (stdlib only).

Used to build a light, REAL demo capture from the CIC-IDS2017 Friday PCAP
(pcapng, ~8.8 GB) without Wireshark tools. Packets whose timestamp falls inside
one of the requested windows are written, unchanged, to a classic libpcap file.

Windows are given in UTC ISO-8601 (``2017-07-07T17:00:00``) or as epoch seconds.
CIC-IDS2017 CSV timestamps are New Brunswick local time (ADT, UTC-3): add 3 h.

Example:
    python3 tools/slice_pcap.py data/cic/raw/pcap/Friday-WorkingHours.pcap \
        data/pcaps/cic_friday_extract.pcap \
        --window 2017-07-07T18:59:00 2017-07-07T19:01:00
"""

from __future__ import annotations

import argparse
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_SPB = 0x00000003
PCAPNG_EPB = 0x00000006
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def parse_time(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        pass
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


class PcapWriter:
    def __init__(self, path: Path, linktype: int):
        self.handle = path.open("wb")
        self.handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        self.count = 0

    def write(self, ts: float, data: bytes, orig_len: int) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.handle.write(struct.pack("<IIII", sec, usec, len(data), orig_len))
        self.handle.write(data)
        self.count += 1

    def close(self) -> None:
        self.handle.close()


def iter_pcapng(handle):
    """Yield (linktype, ts_seconds, data, orig_len) for every timestamped packet."""
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
    while True:
        head = handle.read(8)
        if len(head) < 8:
            return
        raw_type = struct.unpack("<I", head[:4])[0]
        if raw_type == PCAPNG_SHB:
            magic = handle.read(4)
            endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            block_len = struct.unpack(endian + "I", head[4:8])[0]
            handle.seek(block_len - 12, 1)
            interfaces = []
            continue
        block_type, block_len = struct.unpack(endian + "II", head)
        body = handle.read(block_len - 8)
        if len(body) < block_len - 8:
            return
        if block_type == PCAPNG_IDB:
            linktype = struct.unpack(endian + "H", body[:2])[0]
            resolution = 1e-6
            pos = 8
            while pos + 4 <= len(body) - 4:
                code, length = struct.unpack(endian + "HH", body[pos:pos + 4])
                if code == 0:
                    break
                if code == 9 and length >= 1:
                    raw = body[pos + 4]
                    resolution = 2.0 ** -(raw & 0x7F) if raw & 0x80 else 10.0 ** -raw
                pos += 4 + ((length + 3) // 4) * 4
            interfaces.append((linktype, resolution))
        elif block_type == PCAPNG_EPB:
            iface, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            linktype, resolution = interfaces[iface]
            ts = ((ts_high << 32) | ts_low) * resolution
            yield linktype, ts, body[20:20 + cap_len], orig_len
        # SPB (no timestamp) and other block types are skipped.


def iter_pcap(handle, endian: str, ticks: int):
    # Global header after the 4-byte magic: version (2x H), thiszone, sigfigs, snaplen, network.
    linktype = struct.unpack(endian + "HHiIII", handle.read(20))[-1] & 0xFFFF
    while True:
        rec = handle.read(16)
        if len(rec) < 16:
            return
        sec, frac, cap_len, orig_len = struct.unpack(endian + "IIII", rec)
        data = handle.read(cap_len)
        yield linktype, sec + frac / ticks, data, orig_len


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--window", nargs=2, action="append", metavar=("START", "END"), required=True,
                        help="UTC ISO time or epoch seconds; repeatable")
    parser.add_argument("--slack", type=float, default=120.0,
                        help="keep reading this many seconds past the last window (out-of-order packets)")
    args = parser.parse_args()

    windows = sorted((parse_time(a), parse_time(b)) for a, b in args.window)
    if any(start >= end for start, end in windows):
        raise SystemExit("each window needs START < END")
    stop_after = windows[-1][1] + args.slack

    args.output.parent.mkdir(parents=True, exist_ok=True)
    writer = None
    seen = 0
    with args.source.open("rb") as handle:
        magic = handle.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            handle.seek(0)
            packets = iter_pcapng(handle)
        elif magic in PCAP_MAGICS:
            endian, ticks = PCAP_MAGICS[magic]
            packets = iter_pcap(handle, endian, ticks)
        else:
            raise SystemExit(f"{args.source}: not a pcap/pcapng file")

        for linktype, ts, data, orig_len in packets:
            seen += 1
            if ts > stop_after:
                break
            if any(start <= ts < end for start, end in windows):
                if writer is None:
                    writer = PcapWriter(args.output, linktype)
                writer.write(ts, data, orig_len)

    if writer is None:
        print(f"[slice_pcap] no packet inside the windows ({seen} packets read)", file=sys.stderr)
        return 1
    writer.close()
    print(f"[slice_pcap] read {seen} packets, wrote {writer.count} to {args.output} "
          f"({args.output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
