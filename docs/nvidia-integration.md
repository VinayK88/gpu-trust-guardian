# NVIDIA integration boundaries

GPU Trust Guardian runs on CPU by default so reviewers can reproduce the project without specialized hardware. NVIDIA integrations are explicit adapters rather than hidden requirements.

## 1. Live GPU telemetry through NVML

Install the optional dependency and request one bounded snapshot:

```bash
pip install -e ".[nvidia]"
gpu-trust-guardian nvml
```

The adapter reads device identity, driver version, utilization, memory use, and power. It never executes a process or changes GPU state.

## 2. Morpheus ingestion

Export the checked-in event schema as one JSON record per line:

```bash
gpu-trust-guardian morpheus-export \
  --events data/compromised_events.csv \
  --output reports/morpheus-events.jsonl
```

The output is column-oriented for a downstream [NVIDIA Morpheus](https://docs.nvidia.com/morpheus/) source/deserialization stage. This repository does not claim a native Morpheus benchmark because the portable validation environment has no NVIDIA GPU.

## 3. GPU attestation

The checked-in fixtures mirror four policy claims: nonce match, signature verification, trusted measurement, and confidential-computing mode. The demo parser assumes those booleans have already been verified.

For production, replace the fixture adapter with the [NVIDIA Attestation Suite](https://docs.nvidia.com/attestation/index.html), enforce freshness, bind the nonce to the request, validate reference measurements, and fail closed before releasing model keys or confidential inputs.

## 4. NeMo Guardrails

The optional [`guardrails/config.yml`](../guardrails/config.yml) wraps an OpenAI-compatible model with input/output checks. The deterministic application layer remains responsible for tool authorization and human approval, following the principle that model output is untrusted.

## Non-endorsement

This is an independent educational portfolio project. It is not affiliated with, sponsored by, or endorsed by NVIDIA. NVIDIA, CUDA, Morpheus, NeMo, and NVML are referenced only to describe integration surfaces.
