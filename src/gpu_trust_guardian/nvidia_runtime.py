"""Optional NVML telemetry collection with dependency injection for safe tests."""

from __future__ import annotations

from typing import Any


def collect_nvml_snapshot(nvml: Any | None = None) -> list[dict[str, object]]:
    if nvml is None:
        try:
            import pynvml as nvml  # type: ignore[no-redef]
        except ImportError as exc:
            raise RuntimeError(
                "NVML support is optional. Install with: pip install -e '.[nvidia]'"
            ) from exc
    nvml.nvmlInit()
    snapshots: list[dict[str, object]] = []
    try:
        driver = nvml.nvmlSystemGetDriverVersion()
        driver = driver.decode() if isinstance(driver, bytes) else str(driver)
        for index in range(nvml.nvmlDeviceGetCount()):
            handle = nvml.nvmlDeviceGetHandleByIndex(index)
            utilization = nvml.nvmlDeviceGetUtilizationRates(handle)
            memory = nvml.nvmlDeviceGetMemoryInfo(handle)
            name = nvml.nvmlDeviceGetName(handle)
            uuid = nvml.nvmlDeviceGetUUID(handle)
            snapshots.append(
                {
                    "index": index,
                    "name": name.decode() if isinstance(name, bytes) else str(name),
                    "gpu_uuid": uuid.decode() if isinstance(uuid, bytes) else str(uuid),
                    "driver_version": driver,
                    "gpu_utilization_pct": float(utilization.gpu),
                    "memory_utilization_pct": float(utilization.memory),
                    "memory_used_mb": round(memory.used / (1024 * 1024), 2),
                    "power_watts": round(nvml.nvmlDeviceGetPowerUsage(handle) / 1000, 2),
                }
            )
    finally:
        nvml.nvmlShutdown()
    return snapshots
