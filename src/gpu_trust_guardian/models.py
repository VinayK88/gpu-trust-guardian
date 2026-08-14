"""Typed records shared by the simulator, detectors, policy engine, and UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


@dataclass(frozen=True)
class TelemetryEvent:
    timestamp: str
    event_id: str
    user: str
    workload: str
    container_id: str
    gpu_uuid: str
    process: str
    gpu_utilization_pct: float
    memory_utilization_pct: float
    power_watts: float
    bytes_out_mb: float
    destination: str
    image_signed: bool
    privileged: bool
    host_pid_access: bool
    model_access: bool
    model_name: str
    attestation_trusted: bool
    scenario: str
    label: str
    split: str = "demo"

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TelemetryEvent":
        return cls(
            timestamp=str(payload["timestamp"]),
            event_id=str(payload["event_id"]),
            user=str(payload["user"]),
            workload=str(payload["workload"]),
            container_id=str(payload["container_id"]),
            gpu_uuid=str(payload["gpu_uuid"]),
            process=str(payload["process"]),
            gpu_utilization_pct=float(payload["gpu_utilization_pct"]),
            memory_utilization_pct=float(payload["memory_utilization_pct"]),
            power_watts=float(payload["power_watts"]),
            bytes_out_mb=float(payload["bytes_out_mb"]),
            destination=str(payload["destination"]),
            image_signed=_as_bool(payload["image_signed"]),
            privileged=_as_bool(payload["privileged"]),
            host_pid_access=_as_bool(payload["host_pid_access"]),
            model_access=_as_bool(payload["model_access"]),
            model_name=str(payload.get("model_name", "none")),
            attestation_trusted=_as_bool(payload["attestation_trusted"]),
            scenario=str(payload["scenario"]),
            label=str(payload["label"]),
            split=str(payload.get("split", "demo")),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttestationEvidence:
    gpu_uuid: str
    source: str
    nonce_matches: bool
    signature_verified: bool
    measurement_trusted: bool
    cc_mode_enabled: bool
    issued_at: str
    measurement: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AttestationEvidence":
        return cls(
            gpu_uuid=str(payload["gpu_uuid"]),
            source=str(payload.get("source", "synthetic-demo")),
            nonce_matches=_as_bool(payload["nonce_matches"]),
            signature_verified=_as_bool(payload["signature_verified"]),
            measurement_trusted=_as_bool(payload["measurement_trusted"]),
            cc_mode_enabled=_as_bool(payload["cc_mode_enabled"]),
            issued_at=str(payload["issued_at"]),
            measurement=str(payload["measurement"]),
        )

    @property
    def trusted(self) -> bool:
        return all(
            [
                self.nonce_matches,
                self.signature_verified,
                self.measurement_trusted,
                self.cc_mode_enabled,
            ]
        )

    def failed_checks(self) -> list[str]:
        checks = {
            "nonce": self.nonce_matches,
            "signature": self.signature_verified,
            "measurement": self.measurement_trusted,
            "confidential-computing mode": self.cc_mode_enabled,
        }
        return [name for name, passed in checks.items() if not passed]

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "trusted": self.trusted, "failed_checks": self.failed_checks()}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    category: str
    title: str
    subject: str
    evidence: str
    remediation: str
    score: int
    event_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["event_ids"] = list(self.event_ids)
        return payload


@dataclass
class TrustReport:
    scenario: str
    generated_at: str
    source: str
    data_classification: str
    total_events: int
    suspicious_events: int
    attestation: AttestationEvidence
    risk_score: int
    decision: str
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[list[str]] = field(default_factory=list)
    graph_summary: dict[str, int] = field(default_factory=dict)
    top_anomalies: list[dict[str, Any]] = field(default_factory=list)
    runtime: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_counts(self) -> dict[str, int]:
        return {
            level: sum(item.severity == level for item in self.findings)
            for level in ("critical", "high", "medium", "low")
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": "GPU Trust Guardian",
            "scenario": self.scenario,
            "generated_at": self.generated_at,
            "source": self.source,
            "data_classification": self.data_classification,
            "summary": {
                "decision": self.decision,
                "risk_score": self.risk_score,
                "total_events": self.total_events,
                "suspicious_events": self.suspicious_events,
                "attack_paths": len(self.attack_paths),
                "attestation_trusted": self.attestation.trusted,
            },
            "severity_counts": self.severity_counts,
            "attestation": self.attestation.to_dict(),
            "graph_summary": self.graph_summary,
            "runtime": self.runtime,
            "attack_paths": self.attack_paths,
            "top_anomalies": self.top_anomalies,
            "findings": [item.to_dict() for item in self.findings],
            "limitations": [
                "All checked-in telemetry and attack labels are synthetic.",
                "The demo attestation parser does not replace NVIDIA Remote Attestation Service verification.",
                "Synthetic model scores validate the pipeline, not production detection performance.",
            ],
        }
