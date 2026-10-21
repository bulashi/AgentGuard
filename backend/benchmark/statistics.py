from __future__ import annotations

import math
from collections.abc import Iterable


def percentile(values: Iterable[float], quantile: float) -> float:
    samples = sorted(float(value) for value in values)
    if not samples:
        raise ValueError("percentile requires at least one sample")
    if not 0 <= quantile <= 1:
        raise ValueError("quantile must be between zero and one")
    if len(samples) == 1:
        return samples[0]
    position = (len(samples) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return samples[lower]
    weight = position - lower
    return samples[lower] * (1 - weight) + samples[upper] * weight


def latency_summary(values: Iterable[float]) -> dict[str, float | int]:
    samples = [float(value) for value in values]
    if not samples:
        raise ValueError("latency summary requires at least one sample")
    return {
        "count": len(samples),
        "min_ms": round(min(samples), 6),
        "p50_ms": round(percentile(samples, 0.50), 6),
        "p95_ms": round(percentile(samples, 0.95), 6),
        "p99_ms": round(percentile(samples, 0.99), 6),
        "max_ms": round(max(samples), 6),
        "mean_ms": round(sum(samples) / len(samples), 6),
    }
