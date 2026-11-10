#!/usr/bin/env bash
# Build the NFStream training set and the REAL demo extract from the CIC-IDS2017
# Friday PCAP. Requires docker and data/cic/raw/pcap/Friday-WorkingHours.pcap
# (+ the three Friday CSVs in data/cic/raw/). Nothing is downloaded here.
#
# Outputs (all git-ignored, never committed):
#   data/cic/friday_nfstream_flows.csv  NFStream flows of the whole day
#   data/cic/train_nfstream.csv         flows labelled from CIC ground truth,
#                                       demo windows excluded
#   data/pcaps/cic_friday_extract.pcap  real demo capture (the windows below)
set -euo pipefail
cd "$(dirname "$0")/.."

PCAP=data/cic/raw/pcap/Friday-WorkingHours.pcap
[ -f "$PCAP" ] || { echo "missing $PCAP"; exit 1; }

# Demo windows, UTC (CIC local time ADT + 3 h). Chosen from the CIC labels:
#   Bot      10:36:00-10:38:00 local
#   PortScan 15:08:00-15:08:30 local
#   DDoS     16:00:00-16:00:20 local
WINDOWS=(
  2017-07-07T13:36:00 2017-07-07T13:38:00
  2017-07-07T18:08:00 2017-07-07T18:08:30
  2017-07-07T19:00:00 2017-07-07T19:00:20
)
win_args=()
for ((i = 0; i < ${#WINDOWS[@]}; i += 2)); do
  win_args+=("${WINDOWS[i]}" "${WINDOWS[i+1]}")
done

SEC=(--user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:size=4g --cap-drop ALL
     --security-opt no-new-privileges -e HOME=/tmp)

echo "==> 1/3 NFStream over the whole Friday capture (same extractor + timeouts as predict)"
docker run --rm "${SEC[@]}" --memory 8g \
  -v "$PWD/$(dirname "$PCAP"):/data/pcaps:ro" -v "$PWD/data/cic:/data/flows" \
  ai-ids-ips-flow-extractor --pcap "/data/pcaps/$(basename "$PCAP")" \
  --out /data/flows/friday_nfstream_flows.csv

echo "==> 2/3 Label flows from CIC ground truth (5-tuple + time), exclude demo windows"
excl=()
for ((i = 0; i < ${#win_args[@]}; i += 2)); do
  excl+=(--exclude-window "${win_args[i]}" "${win_args[i+1]}")
done
docker run --rm "${SEC[@]}" --memory 8g \
  -v "$PWD/tools:/tools:ro" -v "$PWD/data/cic:/data/cic" \
  --entrypoint python ai-ids-ips-ai-engine /tools/label_nfstream_flows.py "${excl[@]}"

echo "==> 3/3 Cut the real demo extract"
wargs=()
for ((i = 0; i < ${#win_args[@]}; i += 2)); do
  wargs+=(--window "${win_args[i]}" "${win_args[i+1]}")
done
python3 tools/slice_pcap.py "$PCAP" data/pcaps/cic_friday_extract.pcap "${wargs[@]}"
echo "done"
