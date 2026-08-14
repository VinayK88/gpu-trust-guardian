"""Small adapter that emits column-oriented JSON records for Morpheus ingestion."""

from __future__ import annotations

import json
from collections.abc import Iterable

from .models import TelemetryEvent


MORPHEUS_COLUMNS = (
    "timestamp",
    "event_id",
    "user",
    "workload",
    "container_id",
    "gpu_uuid",
    "process",
    "gpu_utilization_pct",
    "memory_utilization_pct",
    "power_watts",
    "bytes_out_mb",
    "destination",
    "image_signed",
    "privileged",
    "host_pid_access",
    "model_access",
    "attestation_trusted",
)


def to_morpheus_record(event: TelemetryEvent) -> dict[str, object]:
    payload = event.to_dict()
    return {column: payload[column] for column in MORPHEUS_COLUMNS}


def to_jsonl(events: Iterable[TelemetryEvent]) -> str:
    return "\n".join(json.dumps(to_morpheus_record(event), sort_keys=True) for event in events) + "\n"
