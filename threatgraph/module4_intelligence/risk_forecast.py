"""Module 4 / component 14 — Risk forecast & trend analysis.

Time-series risk scoring · vulnerability trend modeling · predictive exposure
windows. Implemented with a dependency-free linear trend + exponential smoothing
so it runs anywhere; swap for Prophet/ARIMA in production.
"""
from __future__ import annotations

import random
from typing import Dict, Any, List, Tuple


def synthetic_history(current_risk: float, periods: int = 12,
                      seed: int = 14) -> List[float]:
    """Fabricate a plausible weekly risk history ending near `current_risk`
    (used when no real historical snapshots exist yet)."""
    rng = random.Random(seed)
    series, val = [], max(5.0, current_risk - periods * 1.2)
    for _ in range(periods):
        val = max(0.0, min(100.0, val + rng.uniform(-2, 3.0)))
        series.append(round(val, 1))
    series[-1] = round(current_risk, 1)
    return series


def _linreg(series: List[float]) -> Tuple[float, float]:
    """Ordinary least squares slope/intercept over index 0..n-1."""
    n = len(series)
    xs = list(range(n))
    mx = sum(xs) / n
    my = sum(series) / n
    denom = sum((x - mx) ** 2 for x in xs) or 1.0
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, series)) / denom
    return slope, my - slope * mx


def forecast(series: List[float], horizon: int = 6,
             threshold: float = 75.0) -> Dict[str, Any]:
    slope, intercept = _linreg(series)
    n = len(series)
    preds = [round(min(100.0, max(0.0, intercept + slope * (n + h))), 1)
             for h in range(horizon)]

    # exponential smoothing as a second estimator
    alpha, smoothed = 0.5, series[0]
    for v in series[1:]:
        smoothed = alpha * v + (1 - alpha) * smoothed

    exposure_window = None
    for h, p in enumerate(preds):
        if p >= threshold:
            exposure_window = h + 1     # periods from now until threshold breach
            break

    return {"history": series, "trend_slope": round(slope, 3),
            "smoothed_level": round(smoothed, 1), "forecast": preds,
            "threshold": threshold, "predicted_exposure_window": exposure_window,
            "direction": "rising" if slope > 0.3 else
                         "falling" if slope < -0.3 else "stable"}


def vulnerability_trend(env: Dict[str, Any]) -> Dict[str, Any]:
    """Summarise the current vulnerability posture as a feed into forecasting."""
    vulns = env["vulns"]
    exploitable = [v for v in vulns if v.get("exploit_available")]
    high = [v for v in vulns if v.get("cvss", 0) >= 8.0]
    return {"total_vulns": len(vulns), "exploitable": len(exploitable),
            "high_critical": len(high),
            "mean_cvss": round(sum(v["cvss"] for v in vulns) / max(1, len(vulns)), 1)}