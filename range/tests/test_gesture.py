"""几何任务的测试。

这一层和 VM 挑战的性质不同：路点**不保密**，客户端自己就能算。所以测试的
重点不是"攻击方能不能知道答案"，而是：

  1. 路点确实每请求都变（合成好的轨迹用不了第二次）
  2. 不走路点过不去
  3. 匀速插值过不去（必须有减速剖面）
  4. **真的按剖面走过去的轨迹必须能过** —— 误杀合法客户端比放过攻击方更糟
  5. 配速核对真的会拦住"声称走了很久但其实没等"的请求
"""

from __future__ import annotations

import math

import pytest

from app import gesture
from app.core import RangeState


def walk(
    task: gesture.Task, *, step_ms: float = 20.0, steps: int = 16, ease: bool = True
) -> list[dict]:
    """按路点生成一条轨迹。

    ease=True 用最小抖动剖面 3p²-2p³（端点速度为 0，天然满足"接近时减速"）；
    ease=False 用线性插值，即匀速——它应该被 no_deceleration 拦掉。
    """
    events: list[dict] = []
    t = 0.0
    cx, cy = float(task.waypoints[0][0]), float(task.waypoints[0][1])
    for tx, ty in task.waypoints:
        sx, sy = cx, cy
        for i in range(1, steps + 1):
            p = i / steps
            factor = p * p * (3 - 2 * p) if ease else p
            t += step_ms
            events.append(
                {
                    "t": round(t, 2),
                    "type": "mousemove",
                    "x": round(sx + (tx - sx) * factor),
                    "y": round(sy + (ty - sy) * factor),
                }
            )
        cx, cy = float(tx), float(ty)
    return events


@pytest.fixture
def task() -> gesture.Task:
    return gesture.derive_task("sess-1", "1789000000000", "nonce-a")


# --- 路点派生 ---


def test_same_inputs_give_same_waypoints():
    a = gesture.derive_task("s", "1", "n")
    b = gesture.derive_task("s", "1", "n")
    assert a.waypoints == b.waypoints


def test_waypoints_change_per_request():
    """含 ts 与 nonce，所以每个请求的路点都不同——合成好的轨迹用不了第二次。"""
    base = gesture.derive_task("s", "1789000000000", "n1")
    assert gesture.derive_task("s", "1789000000001", "n1").waypoints != base.waypoints
    assert gesture.derive_task("s", "1789000000000", "n2").waypoints != base.waypoints
    assert gesture.derive_task("s2", "1789000000000", "n1").waypoints != base.waypoints


def test_waypoints_stay_inside_canvas():
    for index in range(30):
        task = gesture.derive_task("s", str(index), "n", width=640, height=360, tolerance=18)
        for x, y in task.waypoints:
            assert 36 <= x <= 640 - 36
            assert 36 <= y <= 360 - 36


def test_waypoints_are_not_all_identical():
    task = gesture.derive_task("s", "1", "n", count=4)
    assert len(set(task.waypoints)) > 1


# --- 核验：合法轨迹必须能过 ---


def test_proper_gesture_passes(task):
    """最重要的一条：真的按减速剖面走过去，必须能过。

    误杀合法客户端比放过攻击方更糟——防御方会因为转化率下跌先把这层关掉。
    """
    result = gesture.verify(task, walk(task))
    assert result.ok, f"合法手势被误杀: {result.reason} {result.detail}"


def test_deceleration_measured_at_closest_point_not_entry(task):
    """回归：减速必须在**最接近路点处**判，不能在刚进容差圈的边界点判。

    刚进圈时指针还在高速接近，在那里测速度会把真实的减速轨迹误判成匀速。
    这条来自一次真实的误杀——真浏览器走完路点后被判 no_deceleration。
    """
    trace = walk(task, steps=20)
    result = gesture.verify(task, trace)
    assert result.ok, f"减速剖面被误判: {result.reason} {result.detail}"


# --- 核验：该拦的要拦住 ---


def test_trace_ignoring_waypoints_is_rejected(task):
    """合成一条统计特征漂亮但不走路点的轨迹 —— traced.py 的做法。"""
    events = [
        {"t": i * 18.0, "type": "mousemove", "x": 500 + i, "y": 300 - i} for i in range(60)
    ]
    result = gesture.verify(task, events)
    assert not result.ok
    assert result.reason == "waypoint_missed"


def test_out_of_order_waypoints_rejected(task):
    """顺序不能乱：倒着走过所有路点也不算完成任务。"""
    reversed_task = gesture.Task(
        tuple(reversed(task.waypoints)), task.tolerance, task.width, task.height
    )
    result = gesture.verify(task, walk(reversed_task))
    assert not result.ok
    assert result.reason == "waypoint_missed"


def test_constant_speed_interpolation_rejected(task):
    """匀速插值能命中所有路点，但过不了减速判据。"""
    result = gesture.verify(task, walk(task, ease=False))
    assert not result.ok
    assert result.reason == "no_deceleration"


def test_too_fast_gesture_rejected(task):
    """把时间戳压缩掉 —— 这是最省事的作弊，必须拦住。"""
    result = gesture.verify(task, walk(task, step_ms=0.05))
    assert not result.ok
    assert result.reason == "gesture_too_fast"


def test_sparse_trace_rejected(task):
    events = [{"t": i * 20.0, "type": "mousemove", "x": x, "y": y} for i, (x, y) in enumerate(task.waypoints)]
    result = gesture.verify(task, events)
    assert not result.ok
    assert result.reason == "trace_too_sparse"


def test_non_move_events_ignored(task):
    """点击类事件不参与几何判定，混进来不应影响结果。"""
    trace = walk(task)
    trace += [{"t": 9999.0, "type": "click", "x": 0, "y": 0}]
    assert gesture.verify(task, trace).ok


# --- 配速核对 ---


def test_pace_budget_allows_first_request():
    """首次请求没有历史，允许预支一次手势的时长。"""
    state = RangeState()
    within, _ = state.claim_gesture_time("s", 1000.0, 800.0)
    assert within


def test_pace_budget_rejects_time_travel():
    """同一会话在 2 秒内提交 10 条各称 800ms 的轨迹 —— 物理上不可能。"""
    state = RangeState()
    now = 1000.0
    state.claim_gesture_time("s", now, 800.0)
    rejected = False
    for index in range(1, 10):
        within, _ = state.claim_gesture_time("s", now + index * 0.05, 800.0)
        if not within:
            rejected = True
            break
    assert rejected, "配速核对没能拦住时间旅行"


def test_pace_budget_allows_honest_waiting():
    """老老实实等够时间的客户端不该被拦。"""
    state = RangeState()
    now = 1000.0
    for index in range(6):
        within, overspend = state.claim_gesture_time("s", now + index * 1.0, 800.0)
        assert within, f"第 {index} 次被误拦，超支 {overspend}ms"


# --- 时长下限 ---


def test_min_duration_tracks_path_length(task):
    assert task.min_duration_ms(3.0) == pytest.approx(task.path_length / 3.0)
    assert task.path_length > 0


def test_xorshift_never_reaches_zero_from_nonzero():
    """0 是 xorshift 的吸收态，一旦落进去路点就全同。"""
    state = 1
    for _ in range(2000):
        state = gesture.xorshift32(state)
        assert state != 0


def test_fnv1a_matches_vm_implementation():
    """gesture 与 vm 两处的 FNV-1a 必须一致，否则两端派生会漂移。"""
    from app import vm

    for text in ("", "a", "foobar", "sess|123|nonce"):
        assert gesture.fnv1a(text) == vm.fnv1a(text)


def test_local_speed_window_is_bounded():
    assert gesture._local_speed([], 0) is None
    assert gesture._local_speed([1.0, 2.0, 3.0], 0) == pytest.approx(1.0)


def test_path_length_is_euclidean():
    task = gesture.Task(((0, 0), (3, 4), (3, 8)), 10, 640, 360)
    assert task.path_length == pytest.approx(5.0 + 4.0)
    assert math.isclose(task.min_duration_ms(1.0), 9.0)
