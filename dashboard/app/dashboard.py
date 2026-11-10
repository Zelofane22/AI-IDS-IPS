from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

LOG_DIR = Path(os.environ.get("LOG_DIR", "/data/logs"))
FLOWS_CSV = Path(os.environ.get("FLOWS_CSV", "/data/flows/flows.csv"))
PREDICTIONS_JSON = Path(os.environ.get("PREDICTIONS_JSON", "/data/predictions/predictions.json"))
REFRESH_SECONDS = int(os.environ.get("REFRESH_SECONDS", "5"))

st.set_page_config(
    page_title="AI-IDS-IPS Hybrid Dashboard",
    page_icon="🛡️",
    layout="wide",
)


def load_flows() -> pd.DataFrame:
    if not FLOWS_CSV.is_file():
        return pd.DataFrame()
    try:
        return pd.read_csv(FLOWS_CSV, low_memory=False)
    except Exception:
        return pd.DataFrame()


def load_predictions() -> dict:
    if not PREDICTIONS_JSON.is_file():
        return {}
    try:
        return json.loads(PREDICTIONS_JSON.read_text())
    except Exception:
        return {}


def load_alerts() -> pd.DataFrame:
    eve = LOG_DIR / "eve.json"
    if not eve.is_file():
        return pd.DataFrame()
    rows = []
    with eve.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert", {})
            rows.append(
                {
                    "timestamp": event.get("timestamp"),
                    "src_ip": event.get("src_ip"),
                    "dst_ip": event.get("dest_ip"),
                    "src_port": event.get("src_port"),
                    "dst_port": event.get("dest_port"),
                    "protocol": str(event.get("proto", "")).upper(),
                    "signature": alert.get("signature"),
                    "severity": alert.get("severity"),
                    "category": alert.get("category"),
                    "action": alert.get("action"),
                    # Set by Suricata (eve "pcap-file: true"); same stem as flow-extractor flow_id prefix.
                    "source_pcap": Path(str(event.get("pcap_filename", ""))).stem,
                }
            )
    return pd.DataFrame(rows)


def normalize_ports(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.copy()
    for column in ("src_port", "dst_port"):
        if column in frame.columns:
            frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(0).astype(int)
        else:
            frame[column] = 0
    return frame


def add_correlation_key(frame: pd.DataFrame) -> pd.DataFrame:
    frame = normalize_ports(frame)
    frame["protocol"] = frame["protocol"].fillna("").astype(str).str.upper()
    frame["key"] = list(
        zip(
            frame["src_ip"].fillna("").astype(str),
            frame["dst_ip"].fillna("").astype(str),
            frame["src_port"],
            frame["dst_port"],
            frame["protocol"],
        )
    )
    return frame


def build_hybrid(alerts: pd.DataFrame, predictions: pd.DataFrame) -> pd.DataFrame:
    if predictions.empty:
        return pd.DataFrame()

    predictions = add_correlation_key(predictions)

    if alerts.empty:
        alert_summary = pd.DataFrame(columns=["key", "alert_count", "signatures"])
    else:
        alerts = add_correlation_key(alerts)
        alert_summary = (
            alerts.groupby("key")
            .agg(
                alert_count=("signature", "count"),
                signatures=("signature", lambda values: " | ".join(sorted(set(map(str, values))))),
            )
            .reset_index()
        )

    hybrid = predictions.merge(alert_summary, on="key", how="left")
    hybrid["alert_count"] = hybrid["alert_count"].fillna(0).astype(int)
    hybrid["signatures"] = hybrid["signatures"].fillna("")

    def decide(row) -> str:
        ai = bool(row["is_attack"])
        ids = row["alert_count"] > 0
        if ai and ids:
            return "high_priority"
        if ids:
            return "suricata_log"
        if ai:
            return "ai_alert"
        return "normal"

    hybrid["decision"] = hybrid.apply(decide, axis=1)
    return hybrid


def render() -> None:
    flows = load_flows()
    prediction_payload = load_predictions()
    alerts = load_alerts()
    predictions = pd.DataFrame(prediction_payload.get("predictions", []))
    sources: dict = prediction_payload.get("sources", {})

    st.title("AI-IDS-IPS — Tableau de bord hybride")
    st.caption(
        "Prototype IDS/IPS hors ligne — Suricata + Random Forest. "
        "Aucun blocage réseau réel n'est effectué."
    )

    # Capture selector: filters on the PCAP name carried by both Suricata events
    # (pcap_filename) and flow ids (flow-extractor prefix) — a real shared field.
    capture_names = sorted(sources)
    selected = "Toutes"
    if len(capture_names) > 1:
        selected = st.selectbox("Capture analysée", ["Toutes"] + capture_names)
    if selected != "Toutes":
        if "source_pcap" in predictions.columns:
            predictions = predictions[predictions["source_pcap"] == selected]
        if "source_pcap" in alerts.columns:
            alerts = alerts[alerts["source_pcap"] == selected]
        if "flow_id" in flows.columns:
            flows = flows[flows["flow_id"].astype(str).str.startswith(selected + ":")]
    shown = capture_names if selected == "Toutes" else [selected]
    hybrid = build_hybrid(alerts, predictions)

    if prediction_payload.get("demo"):
        st.error(
            "Modèle entraîné sur des données SYNTHÉTIQUES de démonstration — "
            "aucun résultat expérimental."
        )
    synthetic = [name for name in shown if sources.get(name, {}).get("synthetic")]
    real = [name for name in shown if not sources.get(name, {}).get("synthetic")]
    if synthetic:
        st.warning(
            f"Trafic synthétique de démonstration ({', '.join(synthetic)}) — "
            "ces prédictions ne sont pas un résultat expérimental."
        )
    if real:
        st.info(
            f"Extrait réel CIC-IDS2017 ({', '.join(real)}) : fenêtres exclues de "
            "l'entraînement du modèle. Rejeu hors ligne, aucun trafic live."
        )

    if not alerts.empty:
        st.info(
            f"Corrélation basée uniquement sur la 5-tuple réelle "
            f"(IP source/destination, ports, protocole). Aucune correspondance supposée."
        )

    left, right = st.columns([3, 1])
    with right:
        if st.button("Rafraîchir maintenant", use_container_width=True):
            st.rerun()
    generated = prediction_payload.get("generated_at", "n/a")
    with left:
        st.caption(
            f"Flux : {len(flows)} · Prédictions : {len(predictions)} · "
            f"Alertes Suricata : {len(alerts)} · MAJ IA : {generated}"
        )

    total_flows = len(flows) if not flows.empty else len(predictions)
    ai_suspicious = int(hybrid["is_attack"].sum()) if not hybrid.empty else 0
    high_priority = (
        int((hybrid["decision"] == "high_priority").sum()) if not hybrid.empty else 0
    )

    columns = st.columns(4)
    columns[0].metric("Flux analysés", total_flows)
    columns[1].metric("Alertes Suricata", len(alerts))
    columns[2].metric("Flux suspects (IA)", ai_suspicious)
    columns[3].metric("Priorité haute (concordant)", high_priority)

    suricata_tab, ai_tab, hybrid_tab, stats_tab = st.tabs(
        ["Suricata seul", "IA seule", "Système hybride", "Statistiques"]
    )

    with suricata_tab:
        st.subheader("Alertes Suricata")
        if alerts.empty:
            st.info("Aucune alerte Suricata (eve.json absent ou vide).")
        else:
            display = alerts[
                [
                    "timestamp",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "protocol",
                    "signature",
                    "severity",
                ]
            ]
            st.dataframe(display, use_container_width=True, hide_index=True)
            by_signature = alerts["signature"].value_counts().rename_axis("signature").reset_index(name="count")
            st.bar_chart(by_signature, x="signature", y="count")

    with ai_tab:
        st.subheader("Classifications IA")
        if predictions.empty:
            st.info("Aucune prédiction disponible (predictions.json absent ou vide).")
        else:
            display = predictions[
                [
                    "flow_id",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "protocol",
                    "label",
                    "attack_probability",
                ]
            ].sort_values("attack_probability", ascending=False)
            st.dataframe(display, use_container_width=True, hide_index=True)

    with hybrid_tab:
        st.subheader("Décisions du moteur hybride")
        if hybrid.empty:
            st.info("Aucune donnée corrélée disponible.")
        else:
            display = hybrid[
                [
                    "decision",
                    "flow_id",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "protocol",
                    "attack_probability",
                    "alert_count",
                    "signatures",
                ]
            ].sort_values(
                by=["decision", "attack_probability"],
                key=lambda series: series.map(
                    {
                        "high_priority": 0,
                        "ai_alert": 1,
                        "suricata_log": 2,
                        "normal": 3,
                    }
                )
                if series.name == "decision"
                else series,
                ascending=[True, False],
            )
            st.dataframe(display, use_container_width=True, hide_index=True)

            st.markdown("### Simulation de blocage")
            st.caption("Action simulée uniquement — aucun pare-feu ni interface réseau n'est modifié.")
            candidates = hybrid[hybrid["decision"].isin(["high_priority", "ai_alert"])]
            if candidates.empty:
                st.info("Aucun flux candidat au blocage.")
            else:
                options = candidates["flow_id"].tolist()
                selected = st.multiselect("Flux à simuler comme bloqués", options)
                if st.button("Simuler le blocage"):
                    current = set(st.session_state.get("simulated_blocked", []))
                    current.update(selected)
                    st.session_state["simulated_blocked"] = sorted(current)
                blocked = st.session_state.get("simulated_blocked", [])
                if blocked:
                    st.success(f"{len(blocked)} flux marqués comme bloqués (simulation).")
                    st.write(blocked)
                if st.button("Réinitialiser la simulation"):
                    st.session_state["simulated_blocked"] = []
                    st.rerun()

    with stats_tab:
        st.subheader("Statistiques")
        if hybrid.empty:
            st.info("Aucune statistique disponible.")
        else:
            decisions = (
                hybrid["decision"]
                .value_counts()
                .rename_axis("decision")
                .reset_index(name="count")
            )
            st.bar_chart(decisions, x="decision", y="count")
        if not flows.empty and "protocol" in flows.columns:
            protocols = (
                flows["protocol"].value_counts().rename_axis("protocol").reset_index(name="count")
            )
            st.bar_chart(protocols, x="protocol", y="count")
        data_source = prediction_payload.get("data_source", "n/a")
        st.write(f"Source des données d'entraînement : `{data_source}`")
        st.write(f"Dernière mise à jour : {datetime.now(timezone.utc).isoformat()}")


fragment = st.fragment(run_every=REFRESH_SECONDS)(render)
fragment()
