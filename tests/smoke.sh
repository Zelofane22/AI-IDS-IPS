#!/usr/bin/env bash
# End-to-end smoke test. Requires Docker with Compose v2 available on PATH.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: 'docker compose' is not available in this shell."
    echo "Enable Docker Desktop WSL integration or run from a distro that has Docker."
    exit 1
fi

echo "==> Regenerating synthetic DEMO pcap"
python3 traffic-generator/generate_demo_pcap.py

echo "==> Resetting previous outputs"
rm -f logs/eve.json logs/fast.log logs/suricata.log
rm -f data/flows/flows.csv
rm -f data/predictions/predictions.json
rm -f data/models/model.joblib data/models/train_report.json

echo "==> Building images"
docker compose build

echo "==> Starting pipeline"
docker compose up -d --remove-orphans

cleanup() {
    echo "==> Container status"
    docker compose ps || true
    docker compose logs --no-color --tail=60 || true
}
trap cleanup EXIT

echo "==> Waiting for artifacts (up to 180s)"
for _ in $(seq 1 90); do
    if [ -f data/predictions/predictions.json ] && [ -f logs/eve.json ] && [ -s data/flows/flows.csv ]; then
        break
    fi
    sleep 2
done

echo "==> Checking dashboard health"
for _ in $(seq 1 60); do
    if python3 - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("http://127.0.0.1:8501/_stcore/health", timeout=3)
PY
    then
        echo "dashboard healthy"
        break
    fi
    sleep 2
done

echo "==> Validating artifacts"
python3 tests/check_outputs.py

echo "==> Smoke test finished OK"
