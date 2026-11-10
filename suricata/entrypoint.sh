#!/bin/sh
set -eu

PCAP_DIR="${PCAP_DIR:-/data/pcaps}"
LOG_DIR="${LOG_DIR:-/var/log/suricata}"
CONFIG="${SURICATA_CONFIG:-/etc/suricata/suricata.yaml}"

mkdir -p "$LOG_DIR"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Copy only real capture files into a clean directory so Suricata never tries
# to parse unrelated files (e.g. .gitkeep) that may live in data/pcaps.
find "$PCAP_DIR" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.pcapng' \) \
    -exec cp {} "$WORK_DIR"/ \; 2>/dev/null || true

if [ -z "$(ls -A "$WORK_DIR" 2>/dev/null)" ]; then
    echo "[suricata] no .pcap/.pcapng file found in $PCAP_DIR; nothing to analyze"
    exit 0
fi

echo "[suricata] analyzing $(ls -1 "$WORK_DIR" | wc -l) capture file(s) from $PCAP_DIR"
exec suricata -r "$WORK_DIR" -c "$CONFIG" -l "$LOG_DIR" --runmode single
