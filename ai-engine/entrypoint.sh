#!/bin/sh
set -eu

MODEL="${MODEL_PATH:-/data/models/model.joblib}"
FLOWS="${FLOWS_CSV:-/data/flows/flows.csv}"
OUT="${PREDICTIONS_PATH:-/data/predictions/predictions.json}"
CIC_SAMPLE="${CIC_SAMPLE:-/data/cic/train.csv}"
# Preferred: CIC ground truth on NFStream flows (same extractor as prediction).
NFSTREAM_SAMPLE="${NFSTREAM_SAMPLE:-/data/cic/train_nfstream.csv}"

mkdir -p "$(dirname "$MODEL")" "$(dirname "$OUT")"

if [ ! -f "$MODEL" ]; then
    if [ -f "$NFSTREAM_SAMPLE" ]; then
        echo "[ai-engine] training on NFStream-labelled dataset: $NFSTREAM_SAMPLE"
        python /app/app/train.py --data "$NFSTREAM_SAMPLE" --out "$MODEL" --final-fit all
    elif [ -f "$CIC_SAMPLE" ]; then
        echo "[ai-engine] WARNING: CICFlowMeter features differ from NFStream ones (domain shift)"
        echo "[ai-engine] training on supplied dataset: $CIC_SAMPLE"
        python /app/app/train.py --data "$CIC_SAMPLE" --out "$MODEL"
    else
        echo "[ai-engine] no model and no dataset; training on synthetic DEMO data"
        python /app/app/train.py --demo --out "$MODEL"
    fi
fi

python /app/app/predict.py --flows "$FLOWS" --model "$MODEL" --out "$OUT" --allow-empty
