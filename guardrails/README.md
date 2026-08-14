# Optional NeMo Guardrails integration

[`config.yml`](./config.yml) is a starter configuration for wrapping an OpenAI-compatible model with input and output self-checks. It is intentionally not the enforcement boundary.

The runnable application-layer controls are in [`src/gpu_trust_guardian/guardrails.py`](../src/gpu_trust_guardian/guardrails.py):

- prompt-injection pattern checks;
- secret redaction and blocking;
- an explicit analyst-tool allowlist;
- mandatory human approval for quarantine;
- deterministic regression fixtures.

Production deployments should add model-specific jailbreak testing, real identity and authorization context, auditable approval state, and the current [NVIDIA NeMo Guardrails security guidance](https://docs.nvidia.com/nemo/guardrails/latest/security/guidelines.html).
