# AGENTS.md — AI-IDS-IPS

Hybrid IDS/IPS prototype (Suricata + Random Forest), dockerized, for a cybersecurity thesis.
This file records constraints that are easy to get wrong. Read it before changing services.

## Current state
- 4 Compose services are implemented: `suricata`, `flow-extractor`, `ai-engine`, `dashboard`.
  A stdlib-only synthetic PCAP generator lives in `traffic-generator/`.
- End-to-end validated with `bash tests/smoke.sh` (Docker 29.9.3 + Compose v5.7.0):
  97-packet demo PCAP → 11 flows, 8 Suricata alerts, model trained (0.992 holdout on
  synthetic demo data), 9 suspicious / 2 benign, dashboard healthy on :8501.
  Re-run it after changing services; do not assume it still passes.
- Artifact flow: `data/pcaps/*.pcap` → `logs/eve.json` (Suricata) + `data/flows/flows.csv`
  (NFStream) → `data/models/model.joblib` + `data/predictions/predictions.json` → dashboard.

## Environment gotchas
- Host: Windows 11 + WSL2. Docker Desktop WSL integration is now enabled and `docker` works.
  Verify with `docker --version` before any Docker step.
- System Python is `python3` 3.12.3 with **no** numpy/pandas/sklearn/nfstream installed.
  Only stdlib checks run locally; full execution needs the containers.
- Services run as `${HOST_UID:-1000}:${HOST_GID:-1000}` so bind-mounted outputs are writable.
  If you hit permission errors, export `HOST_UID=$(id -u) HOST_GID=$(id -g)` before compose.
- Containers use `read_only: true` with `/tmp` tmpfs. NFStream writes a temporary CSV in the
  **current directory** — `flow-extractor/Dockerfile` therefore sets `WORKDIR /tmp`; do not
  change it or `to_pandas()` fails with `Read-only file system`.
- Suricata runs as uid 1000, so the Dockerfile does `chmod -R a+rX /etc/suricata`; without it
  Suricata cannot read classification/reference/threshold config files.

## Commands
```bash
# regenerate synthetic DEMO pcap (writes data/pcaps/synthetic_demo.pcap)
python3 traffic-generator/generate_demo_pcap.py

# full pipeline (one-shot suricata/flow-extractor/ai-engine, then dashboard on :8501)
docker compose build
docker compose up -d

# end-to-end smoke test (requires docker; resets outputs, validates artifacts)
bash tests/smoke.sh

# local checks that do not need docker
python3 tests/check_contract.py       # AI features vs flow-extractor columns
python3 tests/verify_pcap.py
python3 tests/check_outputs.py        # only meaningful after a pipeline run

# retrain explicitly on a supplied CIC-IDS2017 sample (do not auto-download)
cp <sample.csv> data/cic/train.csv
docker compose run --rm --entrypoint python ai-engine \
  /app/app/train.py --data /data/cic/train.csv --out /data/models/model.joblib
```

## Architecture constraints
- `suricata`: `jasonish/suricata:8.0.8` base, offline pcap mode only, local demo rules in
  `suricata/rules/local.rules`, `eve.json` written to `logs/`. No network capture mode.
- `flow-extractor`: NFStream → `data/flows/flows.csv` with flow identity (5-tuple, `flow_id`)
  and statistical features.
- `ai-engine`: separate `train.py` / `predict.py`. Canonical feature list AND imputation live in
  `ai-engine/app/features.py`; both scripts must call `build_feature_matrix`.
  `flow-extractor/app/extract.py` must keep emitting those exact columns (duplicated by
  necessity across containers — change both together).
- `dashboard`: Streamlit, reads only the shared files. Auto-refreshes via `st.fragment(run_every=...)`.

## Non-negotiable rules
- **No real network blocking**; blocking is a dashboard simulation only.
- Containers: no `privileged`, `cap_drop: ALL`, `no-new-privileges`, no unneeded ports, resource limits.
- **Never auto-download** large datasets. CIC-IDS2017 only if the user supplies a compatible file.
- Synthetic data must stay clearly labeled as demo (filename, bundle `data_source`, dashboard warning);
  never present it as real experimental results.
- Train and predict must use the **exact same** feature set and preprocessing.
- Correlation: only link Suricata/flow/AI events via real shared keys (IPs, ports, protocol, flow id).
  Never assume a match without a linking field.
- Always expose three views: Suricata-only, AI-only, hybrid.

## Decision policy
Normal → no action; Suricata alert → log; suspicious AI → alert; concordant detection → high priority.
