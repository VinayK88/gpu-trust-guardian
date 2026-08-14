"""Explainable rules that turn GPU behavior and attestation into evidence."""

from __future__ import annotations

import pandas as pd

from .models import AttestationEvidence, Finding


def _ids(frame: pd.DataFrame, limit: int = 12) -> tuple[str, ...]:
    return tuple(frame["event_id"].astype(str).head(limit).tolist())


def detect_findings(
    frame: pd.DataFrame,
    attestation: AttestationEvidence,
    anomaly_scores: pd.Series,
) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    suspicious: set[str] = set()

    if not attestation.trusted:
        failures = ", ".join(attestation.failed_checks())
        findings.append(
            Finding(
                finding_id="GPU-ATTEST-001",
                severity="critical",
                category="attestation",
                title="GPU trust evidence failed policy",
                subject=attestation.gpu_uuid,
                evidence=f"Failed checks: {failures}. Measurement: {attestation.measurement}.",
                remediation="Do not release model keys or sensitive workloads; verify with NVIDIA attestation services.",
                score=46,
            )
        )

    crypto = frame[
        frame["process"].str.contains("xmrig", case=False, regex=False)
        | (
            (frame["gpu_utilization_pct"] >= 93)
            & (frame["power_watts"] >= 315)
            & (frame["memory_utilization_pct"] <= 45)
            & (frame["external_destination"] == 1)
        )
    ]
    if not crypto.empty:
        suspicious.update(crypto["event_id"].astype(str))
        findings.append(
            Finding(
                finding_id="GPU-BEHAVIOR-001",
                severity="high",
                category="cryptomining",
                title="GPU behavior resembles unauthorized cryptomining",
                subject=str(crypto.iloc[0]["workload"]),
                evidence=(
                    f"{len(crypto)} events combine sustained utilization, high power, low memory use, "
                    "or a synthetic miner-process indicator."
                ),
                remediation="Quarantine the workload, preserve telemetry, and validate the image and owner.",
                score=28,
                event_ids=_ids(crypto),
            )
        )

    exfil = frame[
        (frame["bytes_out_mb"] >= 250)
        & (frame["model_access"] == 1)
        & (frame["external_destination"] == 1)
    ]
    if not exfil.empty:
        suspicious.update(exfil["event_id"].astype(str))
        findings.append(
            Finding(
                finding_id="GPU-EGRESS-001",
                severity="critical",
                category="model-exfiltration",
                title="Large external transfer followed model access",
                subject=str(exfil.iloc[0]["model_name"]),
                evidence=(
                    f"{len(exfil)} events transferred {exfil['bytes_out_mb'].sum():,.1f} MB to synthetic "
                    "external destinations after model access."
                ),
                remediation="Block egress, revoke the workload identity, and validate model artifact access logs.",
                score=42,
                event_ids=_ids(exfil),
            )
        )

    escape = frame[(frame["privileged"] == 1) & (frame["host_pid_access"] == 1)]
    if not escape.empty:
        suspicious.update(escape["event_id"].astype(str))
        findings.append(
            Finding(
                finding_id="GPU-CONTAINER-001",
                severity="critical",
                category="container-escape",
                title="Privileged GPU container reached the host PID namespace",
                subject=str(escape.iloc[0]["container_id"]),
                evidence=f"{len(escape)} events show privileged execution with host PID access.",
                remediation="Terminate the workload and investigate node, container runtime, and service account.",
                score=40,
                event_ids=_ids(escape),
            )
        )

    unsigned_privileged = frame[(frame["unsigned_image"] == 1) & (frame["privileged"] == 1)]
    if not unsigned_privileged.empty:
        suspicious.update(unsigned_privileged["event_id"].astype(str))
        findings.append(
            Finding(
                finding_id="GPU-IMAGE-001",
                severity="high",
                category="workload-integrity",
                title="Unsigned image received privileged GPU access",
                subject=str(unsigned_privileged.iloc[0]["container_id"]),
                evidence=f"{len(unsigned_privileged)} privileged events used an unsigned demo image.",
                remediation="Require signed images and deny privileged GPU containers by default.",
                score=22,
                event_ids=_ids(unsigned_privileged),
            )
        )

    anomaly_mask = anomaly_scores >= 4.25
    anomalous = frame.loc[anomaly_mask]
    if len(anomalous) >= 3:
        suspicious.update(anomalous["event_id"].astype(str))
        findings.append(
            Finding(
                finding_id="GPU-ML-001",
                severity="medium",
                category="digital-fingerprint",
                title="Workload behavior departed from its trusted fingerprint",
                subject=str(anomalous.iloc[0]["workload"]),
                evidence=(
                    f"{len(anomalous)} events exceeded the transparent anomaly threshold; "
                    f"maximum score {float(anomaly_scores.max()):.2f}."
                ),
                remediation="Review the highest-scoring events with workload owner and deployment history.",
                score=14,
                event_ids=_ids(anomalous),
            )
        )

    return findings, suspicious
