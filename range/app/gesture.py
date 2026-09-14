"""几何任务 —— 让 L5 从"校验声明"变成"要求证明"。

原来的 L5 只做一件事：统计客户端**提交的**轨迹，看间隔方差、路径曲率、速度
是否像人。这终究是校验声明——攻击方合成一条统计特征漂亮的轨迹就能过
（harness 里的 traced.py 正是这么干的），而且同一条轨迹可以反复用。

几何任务换了个问法：**服务端每请求指定一组新鲜的路点，轨迹必须真的依次
经过它们。**

与 VM 挑战的区别：任务**不保密**
--------------------------------
路点由 (session, ts, nonce) 确定性派生，客户端自己也能算出来——不需要问
服务端，省一次往返。这不是漏洞，是设计：

    VM 挑战的成本在于"你不知道怎么算"（信息壁垒）
    几何任务的成本在于"你必须真的花时间走过去"（物理壁垒）

后者更像工作量证明：难点不在知道去哪，在于**穿过这些点需要一段无法压缩的
时间**，而且这段时间会被服务端按会话累计核对（见 l5_behavior 的配速检查）。

诚实的局限
----------
几何任务挡不住"会写插值的攻击方"——照着路点生成一条带减速剖面的轨迹是可行
的，只是要多花工时（dev_hours），并且**必须真的等那段时间**。所以它不像 VM
那样是硬壁垒，而是把攻击成本从"一次性合成一条轨迹"抬成"每请求付出真实墙钟
时间"。这一点在文档里明说，不假装它是不可绕过的。
"""

from __future__ import annotations

import math
from dataclasses import dataclass

MASK = 0xFFFFFFFF


def fnv1a(text: str) -> int:
    """32 位 FNV-1a。与 vm.fnv1a 同一套实现，sign.js 里有等价的。"""
    h = 0x811C9DC5
    for byte in text.encode():
        h = ((h ^ byte) * 0x01000193) & MASK
    return h


def xorshift32(state: int) -> int:
    """xorshift32。

    这里不用 vm.py 的 sha256 流，是因为 sign.js 侧要**同步**算路点，而浏览器的
    crypto.subtle 只有异步接口。xorshift 用几行位运算就能在两端逐位对齐。
    """
    state &= MASK
    state ^= (state << 13) & MASK
    state ^= state >> 17
    state ^= (state << 5) & MASK
    return state & MASK


@dataclass(frozen=True)
class Task:
    """一次几何任务：依次经过这些路点。"""

    waypoints: tuple[tuple[int, int], ...]
    tolerance: int
    width: int
    height: int

    @property
    def path_length(self) -> float:
        total = 0.0
        for (x0, y0), (x1, y1) in zip(self.waypoints, self.waypoints[1:]):
            total += math.hypot(x1 - x0, y1 - y0)
        return total

    def min_duration_ms(self, px_per_ms: float) -> float:
        """走完全程至少要多久。这是攻击方无法压缩的那段时间。"""
        return self.path_length / px_per_ms if px_per_ms > 0 else 0.0


def derive_task(
    session: str,
    ts: str,
    nonce: str,
    *,
    count: int = 4,
    width: int = 640,
    height: int = 360,
    tolerance: int = 18,
) -> Task:
    """由 (session, ts, nonce) 确定性派生路点。

    含 ts 与 nonce，所以**每个请求的路点都不同**——一条合成好的轨迹没法反复用。
    服务端按同样方式重算，不需要存任何状态。
    """
    state = fnv1a(f"{session}|{ts}|{nonce}") or 1  # xorshift 的 0 是吸收态
    margin = tolerance * 2
    points: list[tuple[int, int]] = []
    for _ in range(count):
        state = xorshift32(state)
        x = margin + state % max(1, width - 2 * margin)
        state = xorshift32(state)
        y = margin + state % max(1, height - 2 * margin)
        points.append((x, y))
    return Task(tuple(points), tolerance=tolerance, width=width, height=height)


# --- 轨迹核验 ---


@dataclass(frozen=True)
class TaskVerdict:
    ok: bool
    reason: str = ""
    detail: dict | None = None


def _moves(trace: list[dict]) -> list[tuple[float, float, float]]:
    """抽出 (t, x, y) 序列，按时间排序。"""
    out = []
    for event in trace:
        if event.get("type") != "mousemove":
            continue
        try:
            out.append((float(event["t"]), float(event["x"]), float(event["y"])))
        except (KeyError, TypeError, ValueError):
            continue
    return sorted(out)


def verify(
    task: Task,
    trace: list[dict],
    *,
    px_per_ms: float = 3.0,
    decel_ratio: float = 0.85,
) -> TaskVerdict:
    """核验轨迹是否真的依次走过了这组路点。

    三道检查，依次收紧：

    1. **依次命中** —— 每个路点都要在容差内被经过，且顺序不能乱。
    2. **接近时减速** —— 人接近目标会减速（Fitts 律）。匀速插值过得了第 1 条，
       过不了这条。
    3. **时长下限** —— 走完全程的用时不能短于 路径长度 / 速度上限。这是那段
       无法压缩的时间。
    """
    moves = _moves(trace)
    if len(moves) < len(task.waypoints) * 3:
        return TaskVerdict(False, "trace_too_sparse", {"points": len(moves)})

    # 1. 依次命中
    hit_indices: list[int] = []
    cursor = 0
    for order, (wx, wy) in enumerate(task.waypoints):
        entry = None
        for index in range(cursor, len(moves)):
            _, x, y = moves[index]
            if math.hypot(x - wx, y - wy) <= task.tolerance:
                entry = index
                break
        if entry is None:
            return TaskVerdict(
                False,
                "waypoint_missed",
                {"waypoint": order, "target": [wx, wy], "tolerance": task.tolerance},
            )

        # 进圈之后继续走，找**距离最近**的那一点。
        # 减速必须在这里判，不能在刚进圈的边界点判——那时候指针还在高速接近，
        # 会把真实的减速轨迹误判成匀速。
        closest, best = entry, math.hypot(moves[entry][1] - wx, moves[entry][2] - wy)
        index = entry + 1
        while index < len(moves):
            distance = math.hypot(moves[index][1] - wx, moves[index][2] - wy)
            if distance > task.tolerance:
                break
            if distance < best:
                best, closest = distance, index
            index += 1

        hit_indices.append(closest)
        cursor = closest + 1

    # 3'. 时长下限（先算，失败得快）
    duration = moves[-1][0] - moves[0][0]
    required = task.min_duration_ms(px_per_ms)
    if duration < required:
        return TaskVerdict(
            False,
            "gesture_too_fast",
            {"duration_ms": round(duration, 1), "required_ms": round(required, 1)},
        )

    # 2. 接近路点时减速
    speeds = _segment_speeds(moves)
    if speeds:
        mean_speed = sum(speeds) / len(speeds)
        for order, index in enumerate(hit_indices):
            local = _local_speed(speeds, index)
            if local is not None and local > mean_speed * decel_ratio:
                return TaskVerdict(
                    False,
                    "no_deceleration",
                    {
                        "waypoint": order,
                        "local_speed": round(local, 3),
                        "mean_speed": round(mean_speed, 3),
                        "allowed_max": round(mean_speed * decel_ratio, 3),
                    },
                )

    return TaskVerdict(True, detail={"duration_ms": round(duration, 1)})


def _segment_speeds(moves: list[tuple[float, float, float]]) -> list[float]:
    speeds = []
    for (t0, x0, y0), (t1, x1, y1) in zip(moves, moves[1:]):
        dt = t1 - t0
        speeds.append(math.hypot(x1 - x0, y1 - y0) / dt if dt > 0 else 0.0)
    return speeds


def _local_speed(speeds: list[float], index: int) -> float | None:
    """路点附近的局部速度：取命中点前后两段的均值。"""
    window = [s for s in speeds[max(0, index - 1) : index + 1]]
    return sum(window) / len(window) if window else None
