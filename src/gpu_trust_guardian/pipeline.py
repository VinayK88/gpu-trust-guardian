"""End-to-end evidence pipeline."""

from __future__ import annotations

import csv
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from .detectors import detect_findings
from .features import BehaviorProfile, event_frame
from .graph import build_evidence_graph, extract_attack_paths, graph_summary
from .models import AttestationEvidence, TelemetryEvent, TrustReport
from .policy import decide


def analyze_events(
    events: list[TelemetryEvent],
    attestation: AttestationEvidence,
    scenario: str,
    source: str = "synthetic-fixture",
) -> TrustReport:
    if len(events) < 20:
        raise ValueError("At least 20 events are required for a stable demo fingerprint")
    frame = event_frame(events).reset_index(drop=True)
    baseline_rows = frame[frame["label"] == "benign"].head(max(20, int(len(frame) * 0.6)))
    if baseline_rows.empty:
        baseline_rows = frame.head(max(20, int(len(frame) * 0.6)))
    profile = BehaviorProfile.fit(baseline_rows)
    anomaly_scores = profile.score(frame)
    frame["anomaly_score"] = anomaly_scores

    findings, suspicious_ids = detect_findings(frame, attestation, anomaly_scores)
    graph = build_evidence_graph(frame)
    paths = extract_attack_paths(frame, suspicious_ids)
    risk_score, decision = decide(findings, attestation)
    top = frame.nlargest(10, "anomaly_score")[
        [
            "timestamp",
            "event_id",
            "workload",
            "process",
            "destination",
            "label",
            "anomaly_score",
        ]
    ]

    return TrustReport(
        scenario=scenario,
        generated_at=datetime.now(timezone.utc).isoformat(),
        source=source,
        data_classification="synthetic-demo",
        total_events=len(events),
        suspicious_events=len(suspicious_ids),
        attestation=attestation,
        risk_score=risk_score,
        decision=decision,
        findings=findings,
        attack_paths=paths,
        graph_summary=graph_summary(graph),
        top_anomalies=top.to_dict(orient="records"),
        runtime={
            "mode": "cpu-portable-reference",
            "python": platform.python_version(),
            "nvidia_gpu_required": False,
        },
    )


def load_events(path: Path) -> list[TelemetryEvent]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [TelemetryEvent.from_dict(row) for row in csv.DictReader(handle)]


def load_attestation(path: Path) -> AttestationEvidence:
    with path.open(encoding="utf-8") as handle:
        return AttestationEvidence.from_dict(json.load(handle))


def scan_files(events_path: Path, attestation_path: Path, scenario: str) -> TrustReport:
    return analyze_events(
        load_events(events_path),
        load_attestation(attestation_path),
        scenario=scenario,
        source=f"{events_path.name} + {attestation_path.name}",
    )


def write_report(report: TrustReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")


def report_frame(report: TrustReport) -> pd.DataFrame:
    return pd.DataFrame([item.to_dict() for item in report.findings])
