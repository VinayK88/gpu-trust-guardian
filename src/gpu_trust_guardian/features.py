"""Feature engineering and transparent digital-fingerprint scoring."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from .models import TelemetryEvent


FEATURE_COLUMNS = [
    "gpu_utilization_pct",
    "memory_utilization_pct",
    "power_watts",
    "log_bytes_out",
    "external_destination",
    "unsigned_image",
    "privileged",
    "host_pid_access",
    "model_access",
    "utilization_memory_gap",
]


def event_frame(events: list[TelemetryEvent]) -> pd.DataFrame:
    frame = pd.DataFrame([event.to_dict() for event in events])
    return engineer_features(frame)


def engineer_features(frame: pd.DataFrame) -> pd.DataFrame:
    enriched = frame.copy()
    enriched["timestamp"] = pd.to_datetime(enriched["timestamp"], utc=True)
    enriched["log_bytes_out"] = np.log1p(enriched["bytes_out_mb"].astype(float))
    enriched["external_destination"] = enriched["destination"].str.endswith(".invalid").astype(int)
    enriched["unsigned_image"] = (~enriched["image_signed"].astype(bool)).astype(int)
    enriched["privileged"] = enriched["privileged"].astype(int)
    enriched["host_pid_access"] = enriched["host_pid_access"].astype(int)
    enriched["model_access"] = enriched["model_access"].astype(int)
    enriched["attestation_untrusted"] = (~enriched["attestation_trusted"].astype(bool)).astype(int)
    enriched["known_risky_process"] = enriched["process"].str.contains(
        "xmrig|nsenter|export-demo", case=False, regex=True
    ).astype(int)
    enriched["utilization_memory_gap"] = (
        enriched["gpu_utilization_pct"] - enriched["memory_utilization_pct"]
    ).abs()
    enriched["is_attack"] = (enriched["label"] != "benign").astype(int)
    return enriched


@dataclass(frozen=True)
class BehaviorProfile:
    medians: dict[str, float]
    scales: dict[str, float]

    @classmethod
    def fit(cls, frame: pd.DataFrame) -> "BehaviorProfile":
        medians: dict[str, float] = {}
        scales: dict[str, float] = {}
        for column in FEATURE_COLUMNS[:4] + ["utilization_memory_gap"]:
            values = frame[column].astype(float)
            median = float(values.median())
            mad = float((values - median).abs().median())
            medians[column] = median
            scales[column] = max(mad * 1.4826, 0.25)
        return cls(medians=medians, scales=scales)

    def score(self, frame: pd.DataFrame) -> pd.Series:
        numeric = []
        for column in self.medians:
            deviation = (frame[column].astype(float) - self.medians[column]).abs()
            numeric.append((deviation / self.scales[column]).clip(0, 10))
        robust_component = pd.concat(numeric, axis=1).mean(axis=1)
        categorical_component = (
            frame["external_destination"] * 2.0
            + frame["unsigned_image"] * 1.2
            + frame["privileged"] * 2.0
            + frame["host_pid_access"] * 2.5
            + frame["attestation_untrusted"] * 3.0
            + frame["known_risky_process"] * 2.5
        )
        return (robust_component + categorical_component).round(4)
