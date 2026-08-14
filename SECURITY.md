# Security policy

GPU Trust Guardian is a defensive research project built around synthetic telemetry. It does not include exploit code, credential material, malware, or live attack automation.

## Safe-use boundary

- Run included scenarios only in a local development environment.
- Treat every `.invalid` destination as a non-routable demonstration indicator.
- Do not connect the reference response tools to production infrastructure without authentication, authorization, human approval, and audit controls.
- Do not treat the synthetic attestation booleans as cryptographic verification.
- Replace demo evidence adapters with governed NVIDIA and organizational sources before making production decisions.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting feature for this repository. Do not place secrets, private telemetry, exploit payloads, or customer data in a public issue.
