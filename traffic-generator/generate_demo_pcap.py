#!/usr/bin/env python3
"""Generate a small SYNTHETIC DEMO PCAP (stdlib only).

This file is demonstration data. It is never a real capture and any result
derived from it must be labelled as synthetic. It exists so the pipeline can be
exercised end-to-end without downloading a dataset.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

CLIENT_IP = "192.168.1.10"
SERVER_IP = "192.168.1.50"
EXTERNAL_IP = "93.184.216.34"
DNS_IP = "8.8.8.8"

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
GATEWAY_MAC = bytes.fromhex("0200000000fe")

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_bytes(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def ethernet(src_mac: bytes, dst_mac: bytes, ip_packet: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip_packet


def ip_packet(src_ip: str, dst_ip: str, protocol: int, payload: bytes, ident: int) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ident & 0xFFFF,
        0,
        64,
        protocol,
        0,
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    checksum_value = checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ident & 0xFFFF,
        0,
        64,
        protocol,
        checksum_value,
        ip_bytes(src_ip),
        ip_bytes(dst_ip),
    )
    return header + payload


def tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    offset_flags = (5 << 12) | flags
    header = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, offset_flags, 64240, 0, 0
    )
    pseudo = (
        ip_bytes(src_ip)
        + ip_bytes(dst_ip)
        + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    )
    checksum_value = checksum(pseudo + header + payload)
    header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_flags,
        64240,
        checksum_value,
        0,
    )
    return header + payload


def udp_datagram(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = ip_bytes(src_ip) + ip_bytes(dst_ip) + struct.pack("!BBH", 0, 17, length)
    checksum_value = checksum(pseudo + header + payload) or 0xFFFF
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum_value)
    return header + payload


def icmp_echo(identifier: int, sequence: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    checksum_value = checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, checksum_value, identifier, sequence)
    return header + payload


def dns_query(name: str) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return header + question + struct.pack("!HH", 1, 1)


def frame_for(src_ip: str, dst_ip: str, protocol: int, transport: bytes, ident: int) -> bytes:
    src_mac = CLIENT_MAC if src_ip == CLIENT_IP else (SERVER_MAC if src_ip == SERVER_IP else GATEWAY_MAC)
    dst_mac = SERVER_MAC if dst_ip == SERVER_IP else (CLIENT_MAC if dst_ip == CLIENT_IP else GATEWAY_MAC)
    return ethernet(src_mac, dst_mac, ip_packet(src_ip, dst_ip, protocol, transport, ident))


class Emitter:
    def __init__(self) -> None:
        self.packets: list[tuple[float, bytes]] = []
        self.ident = 1

    def _next_ident(self) -> int:
        self.ident = (self.ident + 1) & 0xFFFF
        return self.ident

    def icmp_echo(self, ts: float, src: str, dst: str, seq: int) -> float:
        transport = icmp_echo(0x4242, seq, b"synthetic-demo-payload")
        self.packets.append((ts, frame_for(src, dst, 1, transport, self._next_ident())))
        return ts + 0.002

    def tcp(
        self,
        ts: float,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes = b"",
    ) -> float:
        transport = tcp_segment(src, dst, sport, dport, seq, ack, flags, payload)
        self.packets.append((ts, frame_for(src, dst, 6, transport, self._next_ident())))
        return ts + 0.001

    def tcp_session(
        self,
        ts: float,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        request: bytes = b"",
        response: bytes = b"",
    ) -> float:
        client_seq = 1000 + sport
        server_seq = 5000 + dport

        ts = self.tcp(ts, src, dst, sport, dport, client_seq, 0, SYN)
        ts = self.tcp(ts, dst, src, dport, sport, server_seq, client_seq + 1, SYN | ACK)
        ts = self.tcp(ts, src, dst, sport, dport, client_seq + 1, server_seq + 1, ACK)

        if request:
            ts = self.tcp(
                ts, src, dst, sport, dport, client_seq + 1, server_seq + 1, PSH | ACK, request
            )
            client_seq += len(request)
            ts = self.tcp(ts, dst, src, dport, sport, server_seq + 1, client_seq + 1, ACK)

        if response:
            ts = self.tcp(
                ts, dst, src, dport, sport, server_seq + 1, client_seq + 1, PSH | ACK, response
            )
            server_seq += len(response)
            ts = self.tcp(ts, src, dst, sport, dport, client_seq + 1, server_seq + 1, ACK)

        ts = self.tcp(ts, src, dst, sport, dport, client_seq + 1, server_seq + 1, FIN | ACK)
        ts = self.tcp(ts, dst, src, dport, sport, server_seq + 1, client_seq + 2, FIN | ACK)
        ts = self.tcp(ts, src, dst, sport, dport, client_seq + 2, server_seq + 2, ACK)
        return ts + 0.002

    def tcp_bulk(
        self,
        ts: float,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        chunks: int = 10,
        size: int = 650,
        interval: float = 0.1,
    ) -> float:
        client_seq = 1000 + sport
        server_seq = 5000 + dport

        ts = self.tcp(ts, src, dst, sport, dport, client_seq, 0, SYN)
        ts = self.tcp(ts, dst, src, dport, sport, server_seq, client_seq + 1, SYN | ACK)
        ts = self.tcp(ts, src, dst, sport, dport, client_seq + 1, server_seq + 1, ACK)
        client_seq += 1

        for _ in range(chunks):
            ts = self.tcp(
                ts, dst, src, dport, sport, server_seq + 1, client_seq + 1, PSH | ACK, b"x" * size
            )
            server_seq += size
            ts = self.tcp(ts, src, dst, sport, dport, client_seq + 1, server_seq + 1, ACK)
            ts += interval

        ts = self.tcp(ts, src, dst, sport, dport, client_seq + 1, server_seq + 1, FIN | ACK)
        ts = self.tcp(ts, dst, src, dport, sport, server_seq + 1, client_seq + 2, FIN | ACK)
        ts = self.tcp(ts, src, dst, sport, dport, client_seq + 2, server_seq + 2, ACK)
        return ts + 0.002

    def dns(self, ts: float, src: str, dst: str, sport: int, name: str) -> float:
        query = dns_query(name)
        transport = udp_datagram(src, dst, sport, 53, query)
        self.packets.append((ts, frame_for(src, dst, 17, transport, self._next_ident())))
        return ts + 0.003


def build_demo_capture() -> Emitter:
    emitter = Emitter()
    ts = 1_700_000_000.0

    ts = emitter.icmp_echo(ts, CLIENT_IP, SERVER_IP, 1)

    ts = emitter.tcp_session(
        ts,
        CLIENT_IP,
        SERVER_IP,
        49152,
        80,
        request=b"GET /admin HTTP/1.1\r\nHost: demo.local\r\nUser-Agent: synthetic-demo\r\n\r\n",
        response=b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
    )

    ts = emitter.tcp_session(ts, CLIENT_IP, SERVER_IP, 49153, 22)
    ts = emitter.tcp(ts, CLIENT_IP, SERVER_IP, 49154, 23, 7000, 0, SYN)
    ts = emitter.tcp(ts + 0.001, CLIENT_IP, SERVER_IP, 49155, 3389, 7100, 0, SYN)

    ts = emitter.tcp_session(
        ts + 0.01,
        CLIENT_IP,
        SERVER_IP,
        49156,
        80,
        request=b"GET /index.html HTTP/1.1\r\nHost: demo.local\r\n\r\n",
        response=b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world!",
    )

    ts = emitter.tcp_session(
        ts + 0.01,
        CLIENT_IP,
        EXTERNAL_IP,
        49157,
        443,
        request=b"\x16\x03\x01\x00\x05hello",
        response=b"\x16\x03\x03\x00\x05world",
    )

    ts = emitter.dns(ts + 0.01, CLIENT_IP, DNS_IP, 5353, "example.com")
    ts = emitter.dns(ts + 0.01, CLIENT_IP, DNS_IP, 5354, "demo.local")

    ts = emitter.tcp_bulk(
        ts + 0.01, CLIENT_IP, EXTERNAL_IP, 49158, 443, chunks=10, size=650, interval=0.1
    )
    ts = emitter.tcp_bulk(
        ts + 0.01, CLIENT_IP, SERVER_IP, 49159, 80, chunks=12, size=500, interval=0.08
    )

    return emitter


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in packets:
            seconds = int(timestamp)
            microseconds = int(round((timestamp - seconds) * 1_000_000))
            if microseconds >= 1_000_000:
                seconds += 1
                microseconds -= 1_000_000
            handle.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
            handle.write(frame)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Generate a synthetic DEMO pcap")
    parser.add_argument(
        "--out", type=Path, default=repo_root / "data" / "pcaps" / "synthetic_demo.pcap"
    )
    args = parser.parse_args()

    emitter = build_demo_capture()
    write_pcap(args.out, emitter.packets)
    print(f"[traffic-generator] wrote {len(emitter.packets)} packets to {args.out}")
    print("[traffic-generator] SYNTHETIC DEMO capture -- not real traffic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
