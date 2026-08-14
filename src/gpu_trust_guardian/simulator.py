"""Deterministic, non-exploitative GPU workload telemetry generator."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .models import AttestationEvidence, TelemetryEvent


SCENARIOS = (
    "trusted_training",
    "benign_inference",
    "cryptomining",
    "model_exfiltration",
    "container_escape",
    "untrusted_gpu",
)


def _clamp(value: float, lower: float, upper: float) -> float:
    return round(max(lower, min(upper, value)), 3)


def _external(destination: str) -> bool:
    return destination.endswith(".invalid")


def build_attestation(trusted: bool, gpu_uuid: str = "GPU-DEMO-0001") -> AttestationEvidence:
    return AttestationEvidence(
        gpu_uuid=gpu_uuid,
        source="synthetic-nras-shaped-fixture",
        nonce_matches=trusted,
        signature_verified=trusted,
        measurement_trusted=trusted,
        cc_mode_enabled=trusted,
        issued_at="2026-08-14T05:30:00+00:00",
        measurement="sha384:trusted-demo-rim" if trusted else "sha384:unknown-demo-measurement",
    )


def generate_events(
    scenario: str,
    count: int = 360,
    seed: int = 42,
    split: str = "demo",
) -> list[TelemetryEvent]:
    """Create safe telemetry. Attack rows describe behavior but execute nothing."""

    if scenario not in SCENARIOS and scenario not in {"secure", "compromised"}:
        raise ValueError(f"Unknown scenario: {scenario}")
    rng = random.Random(seed)
    start = datetime(2026, 8, 12, 0, 0, tzinfo=timezone.utc)
    events: list[TelemetryEvent] = []
    attack_start = int(count * 0.72)
    trusted_attestation = scenario not in {"untrusted_gpu", "compromised"}

    for index in range(count):
        timestamp = start + timedelta(minutes=index * 5)
        user_number = index % 8
        workload_number = index % 12
        label = "benign"
        process = "python-train" if index % 3 else "tritonserver"
        utilization = rng.gauss(67, 10)
        memory = rng.gauss(73, 8)
        power = rng.gauss(235, 24)
        bytes_out = max(0.01, rng.lognormvariate(-1.2, 0.55))
        destination = "model-registry.internal"
        image_signed = True
        privileged = False
        host_pid_access = False
        model_access = True
        model_name = "sentinel-7b-demo"

        if scenario == "benign_inference":
            process = "tritonserver"
            utilization = rng.gauss(43, 13)
            memory = rng.gauss(56, 10)
            power = rng.gauss(172, 26)
        if scenario in {"trusted_training", "benign_inference"} and index % 29 == 0:
            process = "model-checkpoint"
            bytes_out = rng.uniform(90, 220)
            destination = "backup.example.invalid"
        if scenario in {"trusted_training", "benign_inference"} and index % 43 == 0:
            process = "cuda-benchmark"
            utilization = rng.gauss(94, 2)
            memory = rng.gauss(48, 7)
            power = rng.gauss(318, 12)
        if scenario in {"trusted_training", "benign_inference"} and index % 61 == 0:
            image_signed = False
        elif scenario in {"cryptomining", "model_exfiltration", "container_escape", "compromised"} and index >= attack_start:
            active_scenario = scenario
            if scenario == "compromised":
                active_scenario = ("cryptomining", "model_exfiltration", "container_escape")[index % 3]
            label = active_scenario
            if active_scenario == "cryptomining":
                process = "xmrig-cuda-demo"
                utilization = rng.gauss(97, 1.8)
                memory = rng.gauss(28, 5)
                power = rng.gauss(348, 10)
                bytes_out = rng.uniform(1.5, 4.0)
                destination = "pool.example.invalid"
                image_signed = False
                model_access = False
                model_name = "none"
                if index % 4 == 0:
                    process = "python-benchmark"
                    utilization = rng.gauss(68, 8)
                    memory = rng.gauss(71, 7)
                    power = rng.gauss(235, 18)
                    destination = "telemetry.partner.internal"
                    image_signed = True
                    model_access = True
                    model_name = "sentinel-7b-demo"
            elif active_scenario == "model_exfiltration":
                process = "python-export-demo"
                utilization = rng.gauss(55, 7)
                memory = rng.gauss(84, 5)
                power = rng.gauss(225, 18)
                bytes_out = rng.uniform(650, 2800)
                destination = "object-store.example.invalid"
                image_signed = False
                if index % 4 == 0:
                    process = "python-checkpoint"
                    bytes_out = rng.uniform(75, 210)
                    destination = "backup.internal"
                    image_signed = True
            elif active_scenario == "container_escape":
                process = "nsenter-demo"
                utilization = rng.gauss(32, 5)
                memory = rng.gauss(24, 6)
                power = rng.gauss(138, 15)
                bytes_out = rng.uniform(0.1, 1.0)
                destination = "host-kernel"
                image_signed = False
                privileged = True
                host_pid_access = True
                model_access = False
                model_name = "none"
                if index % 4 == 0:
                    process = "debug-helper"
                    privileged = False
                    host_pid_access = False
                    image_signed = True
                    utilization = rng.gauss(66, 9)
                    memory = rng.gauss(70, 8)
                    power = rng.gauss(232, 20)
        elif scenario == "untrusted_gpu":
            # Attestation is evaluated by the policy gate, not leaked into the behavior-model label.
            label = "benign"

        destination = str(destination)
        event = TelemetryEvent(
            timestamp=timestamp.isoformat(),
            event_id=f"evt-{scenario[:8]}-{index:04d}",
            user=f"user-{user_number:02d}",
            workload=f"job-{workload_number:02d}",
            container_id=f"ctr-{workload_number:02d}",
            gpu_uuid=f"GPU-DEMO-{workload_number % 3 + 1:04d}",
            process=process,
            gpu_utilization_pct=_clamp(utilization, 0, 100),
            memory_utilization_pct=_clamp(memory, 0, 100),
            power_watts=_clamp(power, 45, 400),
            bytes_out_mb=round(bytes_out, 3),
            destination=destination,
            image_signed=image_signed,
            privileged=privileged,
            host_pid_access=host_pid_access,
            model_access=model_access,
            model_name=model_name,
            attestation_trusted=trusted_attestation,
            scenario=scenario,
            label=label,
            split=split,
        )
        events.append(event)
    return events


def generate_corpus(events_per_scenario: int = 220, seed: int = 42) -> list[TelemetryEvent]:
    rows: list[TelemetryEvent] = []
    for scenario_index, scenario in enumerate(SCENARIOS):
        base = generate_events(scenario, events_per_scenario, seed + scenario_index * 17)
        for row_index, event in enumerate(base):
            evasive_variant = event.process in {"python-benchmark", "python-checkpoint", "debug-helper"}
            challenge_holdout = evasive_variant and row_index % 8 == 0
            split = "test" if challenge_holdout or (row_index + scenario_index) % 6 == 0 else "train"
            rows.append(TelemetryEvent.from_dict({**event.to_dict(), "split": split}))
    return rows


def rows(events: Iterable[TelemetryEvent]) -> list[dict[str, object]]:
    return [event.to_dict() for event in events]
