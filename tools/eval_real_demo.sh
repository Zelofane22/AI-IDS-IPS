#!/usr/bin/env bash
# Score AI / Suricata / hybrid on the real CIC extract after a pipeline run.
# Labels are rebuilt from the CURRENT data/flows/flows.csv: NFStream flow ids are
# not stable across runs (multi-threaded meters), so old label files must not be reused.
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges --memory 4g -e HOME=/tmp \
  -v "$PWD/tools:/tools:ro" -v "$PWD/data/cic:/data/cic" -v "$PWD/data/flows:/data/flows:ro" \
  --entrypoint python ai-ids-ips-ai-engine /tools/label_nfstream_flows.py \
  --flows /data/flows/flows.csv --out /data/cic/demo_labels.csv --max-rows 100000000 >/dev/null
python3 tools/eval_demo.py --labels data/cic/demo_labels.csv
