"""Interactive command center for the checked-in synthetic GPU security range."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gpu_trust_guardian.features import BehaviorProfile, event_frame  # noqa: E402
from gpu_trust_guardian.pipeline import analyze_events, load_attestation, load_events  # noqa: E402
from gpu_trust_guardian.simulator import build_attestation  # noqa: E402


INK = "#142113"
NVIDIA = "#76B900"
ORANGE = "#f97316"
GOLD = "#d9a404"
BLUE = "#2563eb"
PINK = "#db2777"
GRID = "#e5e7eb"
PALETTE = {
    "benign": "#94a3b8",
    "cryptomining": ORANGE,
    "model_exfiltration": PINK,
    "container_escape": GOLD,
}


st.set_page_config(page_title="GPU Trust Guardian", page_icon="🟩", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: #f7faf6; color: #142113; }
    [data-testid="stMetric"] { background: #ffffff; border: 1px solid #dfe7dc;
      border-radius: 14px; padding: 15px; box-shadow: 0 8px 24px rgba(20,33,19,.055); }
    .gpu-hero { background: linear-gradient(115deg,#eef8e6,#ffffff 68%);
      border: 1px solid #c9dda9; border-radius: 20px; padding: 24px 28px; margin-bottom: 18px; }
    .gpu-kicker { color: #4f7d00; font-weight: 800; letter-spacing: .1em; font-size: .78rem; }
    .gpu-hero h1 { color: #142113; margin: .2rem 0 .35rem; }
    .gpu-sub { color: #536350; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_scenario(scenario: str):
    events_path = ROOT / "data" / f"{scenario}_events.csv"
    attestation_path = ROOT / "attestations" / ("trusted.json" if scenario == "secure" else "untrusted.json")
    return load_events(events_path), load_attestation(attestation_path)


def style_figure(figure: go.Figure, title: str, subtitle: str) -> go.Figure:
    figure.update_layout(
        title={"text": f"{title}<br><sup>{subtitle}</sup>", "x": 0.02, "xanchor": "left"},
        paper_bgcolor="white",
        plot_bgcolor="white",
        font={"color": INK},
        margin={"l": 45, "r": 25, "t": 90, "b": 45},
        legend={"orientation": "h", "y": 1.02, "x": 0},
    )
    figure.update_xaxes(gridcolor=GRID, zerolinecolor=GRID)
    figure.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return figure


st.markdown(
    """
    <div class="gpu-hero">
      <div class="gpu-kicker">NVIDIA-FOCUSED AI INFRASTRUCTURE SECURITY LAB</div>
      <h1>GPU Trust Guardian</h1>
      <div class="gpu-sub">Should this GPU workload receive model access—or be quarantined before sensitive data is released?</div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Trust simulation")
    scenario = st.selectbox("Scenario", ["compromised", "secure"], index=0)
    trust_override = st.checkbox("Simulate trusted attestation", value=False, disabled=scenario == "secure")
    st.caption("All included events, identities, destinations, and attacks are synthetic.")
    st.divider()
    st.markdown("**Decision policy**")
    st.caption("ALLOW: no material evidence · QUARANTINE: high-risk behavior · BLOCK: critical evidence or failed attestation")

try:
    events, attestation = load_scenario(scenario)
    if trust_override:
        attestation = build_attestation(True)
    report = analyze_events(events, attestation, scenario)
    frame = event_frame(events)
    profile = BehaviorProfile.fit(frame[frame["label"] == "benign"].head(216))
    frame["anomaly_score"] = profile.score(frame)
except Exception as exc:
    st.error(f"The synthetic scenario could not be loaded: {exc}")
    st.stop()

metric_columns = st.columns(6)
metric_columns[0].metric("Policy decision", report.decision)
metric_columns[1].metric("Risk score", f"{report.risk_score}/100")
metric_columns[2].metric("Suspicious events", report.suspicious_events)
metric_columns[3].metric("Attack paths", len(report.attack_paths))
metric_columns[4].metric("GPU trust", "VERIFIED" if report.attestation.trusted else "FAILED")
metric_columns[5].metric("Telemetry events", report.total_events)

if report.decision == "BLOCK":
    st.error("Sensitive workload blocked: preserve evidence and do not release model keys.")
elif report.decision == "QUARANTINE":
    st.warning("Workload quarantined: analyst validation is required before access is restored.")
else:
    st.success("No blocking evidence found in this bounded simulation; continue normal controls.")

frame["time_bucket"] = frame["timestamp"].dt.floor("30min")
timeline = frame.groupby("time_bucket", as_index=False).agg(
    mean_anomaly_score=("anomaly_score", "mean"),
    event_count=("event_id", "count"),
)
timeline_figure = px.line(
    timeline,
    x="time_bucket",
    y="mean_anomaly_score",
    markers=True,
    color_discrete_sequence=[NVIDIA],
)
timeline_figure.update_traces(line_width=3, marker_size=6)
style_figure(
    timeline_figure,
    "Behavioral risk over time",
    "Mean transparent fingerprint score per 30-minute window; synthetic UTC telemetry",
)
timeline_figure.update_yaxes(title="Mean anomaly score", rangemode="tozero")
timeline_figure.update_xaxes(title="Time (UTC)")
st.plotly_chart(timeline_figure, use_container_width=True)

left, right = st.columns(2)
with left:
    label_counts = (
        frame.groupby("label", as_index=False).size().rename(columns={"size": "events"}).sort_values("events")
    )
    label_figure = px.bar(
        label_counts,
        x="events",
        y="label",
        orientation="h",
        text="events",
        color="label",
        color_discrete_map=PALETTE,
    )
    label_figure.update_layout(showlegend=False)
    style_figure(label_figure, "Telemetry by behavior label", "Event counts in the selected safe scenario")
    label_figure.update_xaxes(title="Events", rangemode="tozero")
    label_figure.update_yaxes(title="")
    st.plotly_chart(label_figure, use_container_width=True)

with right:
    scatter_figure = px.scatter(
        frame,
        x="gpu_utilization_pct",
        y="bytes_out_mb",
        color="label",
        color_discrete_map=PALETTE,
        hover_data=["workload", "process", "destination", "anomaly_score"],
        opacity=0.72,
        log_y=True,
    )
    style_figure(
        scatter_figure,
        "GPU utilization and network egress",
        f"One point per event; n={len(frame):,}; logarithmic egress axis",
    )
    scatter_figure.update_xaxes(title="GPU utilization (%)", range=[0, 102])
    scatter_figure.update_yaxes(title="Outbound transfer (MB, log scale)")
    st.plotly_chart(scatter_figure, use_container_width=True)

st.subheader("Evidence-backed findings")
finding_rows = [
    {
        "Severity": finding.severity.upper(),
        "Category": finding.category,
        "Finding": finding.title,
        "Evidence": finding.evidence,
        "Recommended action": finding.remediation,
    }
    for finding in report.findings
]
if finding_rows:
    st.table(pd.DataFrame(finding_rows).head(12))
else:
    st.info("No findings were produced by the bounded demo detectors.")

st.subheader("Attack-path evidence")
if report.attack_paths:
    for path in report.attack_paths[:8]:
        st.code("  →  ".join(path), language=None)
    if len(report.attack_paths) > 8:
        st.caption(f"Showing 8 of {len(report.attack_paths)} unique evidence paths.")
else:
    st.info("No suspicious identity-to-GPU-to-destination path was observed.")

report_payload = json.dumps(report.to_dict(), indent=2, default=str)
st.download_button("Download JSON evidence report", report_payload, "gpu-trust-report.json", "application/json")
st.caption(
    "Independent portfolio project; not affiliated with or endorsed by NVIDIA. "
    "The CPU reference path runs everywhere. Optional NVML, Morpheus, NeMo Guardrails, and NVIDIA attestation integrations are documented separately."
)
