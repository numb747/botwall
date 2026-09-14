"""L5 行为层 —— 只看交互事件序列的统计特征。

判据全部是分布层面的，不看单个事件。原因很简单：单个事件可以随便伪造，
而让一整串事件的间隔分布、路径曲率、加速度连续性同时像人，需要真正驱动
一个浏览器并产生可信交互。

被本层拦住意味着需要真浏览器 + 可信交互，这是成本阶梯上最贵的一级。
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from typing import Any, ClassVar

from ..core import Probe, RangeState, Strength, Verdict
from .base import Layer


def _intervals(events: list[dict[str, Any]]) -> list[float]:
    ts = [float(e["t"]) for e in events]
    return [b - a for a, b in zip(ts, ts[1:])]


def _coefficient_of_variation(values: list[float]) -> float:
    """变异系数 = 标准差 / 均值。

    人类的事件间隔是长尾的，CV 通常显著大于 0；脚本用固定 sleep 产生的间隔
    CV 接近 0。用 CV 而不是方差，是为了对整体快慢不敏感——放慢一倍的脚本
    方差会变但 CV 不变。
    """
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean <= 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(var) / mean


def _path_straightness(points: list[tuple[float, float]]) -> float:
    """路径的"直线度"：首尾直线距离 / 实际路径长度，取值 (0, 1]。

    完美直线为 1.0。人类的指针轨迹总有抖动和过冲，通常明显小于 1。
    """
    if len(points) < 3:
        return 1.0
    total = 0.0
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        total += math.hypot(x1 - x0, y1 - y0)
    if total <= 0:
        return 1.0
    direct = math.hypot(points[-1][0] - points[0][0], points[-1][1] - points[0][1])
    return min(direct / total, 1.0)


def _speed_cv(points: list[tuple[float, float]], times: list[float]) -> float:
    """逐段速度的变异系数。匀速位移是最强的机器信号。"""
    speeds: list[float] = []
    for (x0, y0), (x1, y1), t0, t1 in zip(points, points[1:], times, times[1:]):
        dt = t1 - t0
        if dt > 0:
            speeds.append(math.hypot(x1 - x0, y1 - y0) / dt)
    return _coefficient_of_variation(speeds)


class BehaviorLayer(Layer):
    id: ClassVar[str] = "l5_behavior"
    name: ClassVar[str] = "行为层"
    ladder_rung: ClassVar[int] = 5  # 被拦 -> 真浏览器 + 可信交互，即阶梯 L5

    #: 一次可信的点击至少要经历的事件序列
    REQUIRED_SEQUENCE: ClassVar[tuple[str, ...]] = ("mousemove", "mousedown", "mouseup", "click")

    def inspect(self, probe: Probe, state: RangeState) -> Verdict:
        raw = probe.header("x-bw-trace")
        if not raw:
            return self._fail("trace_missing", score=float(self.opt("missing_score", 1.0)))

        try:
            events = json.loads(base64.b64decode(raw, validate=True))
        except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
            return self._fail("trace_malformed", detail_error=str(exc))
        if not isinstance(events, list):
            return self._fail("trace_malformed", detail_error="顶层不是数组")

        min_events = int(self.opt("min_events", 8))
        if len(events) < min_events:
            return self._fail("trace_too_short", observed=len(events), required=min_events)

        try:
            events = sorted(events, key=lambda e: float(e["t"]))
            types = [str(e["type"]) for e in events]
        except (KeyError, TypeError, ValueError) as exc:
            return self._fail("trace_malformed", detail_error=f"事件字段缺失或非法: {exc}")

        # --- lenient：只查事件序列完整性 ---
        missing = [t for t in self.REQUIRED_SEQUENCE if t not in types]
        if missing:
            return self._fail("event_sequence_incomplete", missing=missing)
        if types.index("mousemove") > types.index("mousedown"):
            return self._fail("event_sequence_incomplete", detail_note="mousedown 先于任何 mousemove")

        if self.strength is Strength.LENIENT:
            return self._ok(checked="sequence_only", events=len(events))

        # --- strict：间隔分布 ---
        gaps = _intervals(events)
        cv = _coefficient_of_variation(gaps)
        min_cv = float(self.opt("min_interval_cv", 0.25))
        if cv < min_cv:
            return self._fail(
                "interval_variance_low",
                score=float(self.opt("interval_score", 1.0)),
                interval_cv=round(cv, 4),
                required_min=min_cv,
            )

        if self.strength is Strength.STRICT:
            return self._ok(checked="intervals", interval_cv=round(cv, 4))

        # --- paranoid：路径曲率与速度连续性 ---
        moves = [e for e in events if e["type"] == "mousemove" and "x" in e and "y" in e]
        if len(moves) < 5:
            return self._fail("path_unnatural", detail_note="mousemove 采样点不足", observed=len(moves))

        points = [(float(e["x"]), float(e["y"])) for e in moves]
        times = [float(e["t"]) for e in moves]

        straightness = _path_straightness(points)
        max_straightness = float(self.opt("max_straightness", 0.98))
        if straightness > max_straightness:
            return self._fail(
                "path_unnatural",
                detail_note="轨迹接近完美直线",
                straightness=round(straightness, 4),
                allowed_max=max_straightness,
            )

        speed_cv = _speed_cv(points, times)
        min_speed_cv = float(self.opt("min_speed_cv", 0.20))
        if speed_cv < min_speed_cv:
            return self._fail(
                "path_unnatural",
                detail_note="匀速位移",
                speed_cv=round(speed_cv, 4),
                required_min=min_speed_cv,
            )

        return self._ok(
            checked="full",
            interval_cv=round(cv, 4),
            straightness=round(straightness, 4),
            speed_cv=round(speed_cv, 4),
        )
