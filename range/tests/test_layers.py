"""靶场的行为测试。

重点不是覆盖率，而是钉死两件事：
  1. 每一层在该拦的时候拦、该放的时候放
  2. **归因是对的** —— reason 和 ladder_rung 必须准确，
     因为整个成本模型都建立在"被第 N 层拦住"这个判断上
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest

from app import signing
from app.core import Probe, RangeState, Strength
from app.gate import Gate
from app.layers import (
    BehaviorLayer,
    CaptchaLayer,
    NetworkLayer,
    ProtocolLayer,
    RuntimeLayer,
    TransportLayer,
)


# --- 构造工具 ---


def make_probe(**overrides) -> Probe:
    base = dict(
        method="GET",
        path="/api/items",
        query={"limit": "20", "offset": "0"},
        headers={},
        cookies={},
        body=b"",
        client_ip="203.0.113.10",
        received_at=time.time(),
    )
    base.update(overrides)
    base["headers"] = {k.lower(): v for k, v in base["headers"].items()}
    return Probe(**base)


def signed_headers(
    probe: Probe, *, salt_mode="derived", seed="s", static_salt="bw-demo-salt", env=""
) -> dict[str, str]:
    ts = str(int(probe.received_at * 1000))
    nonce = hashlib.sha256(f"{ts}{probe.path}".encode()).hexdigest()[:16]
    sig = signing.compute(
        salt_mode=salt_mode,
        seed=seed,
        static_salt=static_salt,
        env_snapshot=env,
        method=probe.method,
        path=probe.path,
        canonical_query=probe.canonical_query,
        ts=ts,
        nonce=nonce,
    )
    headers = {"x-bw-ts": ts, "x-bw-nonce": nonce, "x-bw-sign": sig}
    if env:
        headers["x-bw-env"] = env
    return headers


def b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


@pytest.fixture
def state() -> RangeState:
    return RangeState()


# --- L1 网络层 ---


def test_l1_rate_limit(state):
    layer = NetworkLayer(Strength.LENIENT, {"window_seconds": 60, "max_requests": 3})
    probe = make_probe()
    for _ in range(3):
        assert layer.inspect(probe, state).passed
    verdict = layer.inspect(probe, state)
    assert not verdict.passed
    assert verdict.reason == "rate_exceeded"


def test_l1_datacenter_rejected_only_at_strict(state):
    probe = make_probe(client_ip="3.1.2.3")  # AWS 段
    lenient = NetworkLayer(Strength.LENIENT, {"max_requests": 100})
    assert lenient.inspect(probe, state).passed

    strict = NetworkLayer(Strength.STRICT, {"max_requests": 100})
    verdict = strict.inspect(probe, RangeState())
    assert not verdict.passed
    assert verdict.reason == "datacenter_asn"
    # 归因：被 L1 拦住意味着要升级到住宅/移动 IP，即成本阶梯 L2
    assert verdict.ladder_rung == 2


def test_l1_local_ip_allowed(state):
    strict = NetworkLayer(Strength.STRICT, {"max_requests": 100, "allow_local": True})
    assert strict.inspect(make_probe(client_ip="127.0.0.1"), state).passed


# --- L2 传输层 ---


FP = {
    "script_clients": {"JA3_REQUESTS": "python-requests"},
    "browsers": {"JA3_CHROME": "chrome", "JA3_FIREFOX": "firefox"},
}


def test_l2_script_client_always_rejected(state):
    layer = TransportLayer(Strength.LENIENT, {"fingerprints": FP})
    verdict = layer.inspect(make_probe(headers={"X-BW-JA3": "JA3_REQUESTS"}), state)
    assert not verdict.passed
    assert verdict.reason == "ja3_known_script_client"
    # 关键：被 L2 拦住不需要离开阶梯 L0，换个客户端库即可
    assert verdict.ladder_rung == 0


def test_l2_allowlist_only_at_strict(state):
    probe = make_probe(headers={"X-BW-JA3": "JA3_UNKNOWN"})
    assert TransportLayer(Strength.LENIENT, {"fingerprints": FP}).inspect(probe, state).passed
    verdict = TransportLayer(Strength.STRICT, {"fingerprints": FP}).inspect(probe, state)
    assert verdict.reason == "ja3_not_in_allowlist"


def test_l2_ua_cross_check(state):
    layer = TransportLayer(Strength.PARANOID, {"fingerprints": FP})
    # 握手是 Firefox 的形状，UA 却自称 Chrome
    probe = make_probe(
        headers={
            "X-BW-JA3": "JA3_FIREFOX",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/142.0.0.0 Safari/537.36",
        }
    )
    verdict = layer.inspect(probe, state)
    assert verdict.reason == "ja3_ua_mismatch"
    assert verdict.detail["ja3_family"] == "firefox"
    assert verdict.detail["ua_family"] == "chrome"


def test_l2_consistent_passes(state):
    layer = TransportLayer(Strength.PARANOID, {"fingerprints": FP})
    probe = make_probe(
        headers={
            "X-BW-JA3": "JA3_CHROME",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/142.0.0.0 Safari/537.36",
        }
    )
    assert layer.inspect(probe, state).passed


# --- L3 协议层 ---


def test_l3_valid_signature(state):
    layer = ProtocolLayer(Strength.STRICT, {"salt_mode": "derived", "seed": "s"})
    probe = make_probe()
    probe = make_probe(headers=signed_headers(probe))
    assert layer.inspect(probe, state).passed


def test_l3_missing_headers(state):
    layer = ProtocolLayer(Strength.STRICT, {"salt_mode": "derived", "seed": "s"})
    verdict = layer.inspect(make_probe(), state)
    assert verdict.reason == "sign_missing"
    assert verdict.ladder_rung == 1


def test_l3_nonce_replay_blocked(state):
    """抓一个包反复重放——最廉价的攻击路径，必须失效。"""
    layer = ProtocolLayer(Strength.STRICT, {"salt_mode": "derived", "seed": "s"})
    probe = make_probe()
    probe = make_probe(headers=signed_headers(probe))
    assert layer.inspect(probe, state).passed
    verdict = layer.inspect(probe, state)
    assert verdict.reason == "nonce_replayed"


def test_l3_stale_timestamp(state):
    layer = ProtocolLayer(Strength.STRICT, {"salt_mode": "derived", "seed": "s", "ts_window_seconds": 10})
    old = time.time() - 120
    probe = make_probe(received_at=old)
    headers = signed_headers(probe)
    # 签名本身有效，但时间戳过期
    probe = make_probe(received_at=time.time(), headers=headers)
    assert layer.inspect(probe, state).reason == "ts_expired"


def test_l3_query_order_does_not_matter(state):
    """canonical_query 按 key 排序，所以参数顺序不影响签名。"""
    layer = ProtocolLayer(Strength.STRICT, {"salt_mode": "derived", "seed": "s"})
    p1 = make_probe(query={"limit": "20", "offset": "0"})
    p2 = make_probe(query={"offset": "0", "limit": "20"})
    assert p1.canonical_query == p2.canonical_query
    assert layer.inspect(make_probe(query=p2.query, headers=signed_headers(p1)), state).passed


def test_l3_runtime_mode_binds_env(state):
    """runtime 档：换掉环境快照，签名就失效。这是 L3 与 L4 的耦合点。"""
    layer = ProtocolLayer(Strength.STRICT, {"salt_mode": "runtime", "seed": "s"})
    env = b64({"userAgent": "x"})
    probe = make_probe()
    headers = signed_headers(probe, salt_mode="runtime", seed="s", env=env)
    assert layer.inspect(make_probe(headers=headers), state).passed

    tampered = dict(headers, **{"x-bw-env": b64({"userAgent": "y"})})
    assert layer.inspect(make_probe(headers=tampered), RangeState()).reason == "sign_mismatch"


def test_l3_lenient_leaks_expected_value(state):
    """lenient 是教学档，会给出期望签名。确认它确实泄露，且 strict 不泄露。"""
    lenient = ProtocolLayer(Strength.LENIENT, {"salt_mode": "derived", "seed": "s"})
    probe = make_probe(headers={"x-bw-ts": str(int(time.time() * 1000)), "x-bw-nonce": "n1", "x-bw-sign": "bad"})
    verdict = lenient.inspect(probe, state)
    assert "expected" in verdict.detail

    strict = ProtocolLayer(Strength.STRICT, {"salt_mode": "derived", "seed": "s"})
    probe2 = make_probe(headers={"x-bw-ts": str(int(time.time() * 1000)), "x-bw-nonce": "n2", "x-bw-sign": "bad"})
    assert "expected" not in strict.inspect(probe2, state).detail


# --- L4 运行时层 ---


GOOD_ENV = {
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/142.0.0.0 Safari/537.36",
    "platform": "Win32",
    "languages": ["zh-CN", "zh"],
    "hardwareConcurrency": 8,
    "webdriver": False,
    "webglVendor": "Google Inc.",
    "webglRenderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
    "canvasHash": "a1b2c3d4e5f60718",
    "windowKeys": [],
    "collectMs": 12.5,
}


def env_probe(env: dict) -> Probe:
    return make_probe(headers={"X-BW-Env": b64(env), "User-Agent": env.get("userAgent", "")})


def test_l4_good_env_passes(state):
    assert RuntimeLayer(Strength.PARANOID).inspect(env_probe(GOOD_ENV), state).passed


def test_l4_webdriver_flag(state):
    verdict = RuntimeLayer(Strength.LENIENT).inspect(env_probe({**GOOD_ENV, "webdriver": True}), state)
    assert verdict.reason == "webdriver_flag"
    assert verdict.ladder_rung == 4


def test_l4_cdp_residue(state):
    env = {**GOOD_ENV, "windowKeys": ["cdc_adoQpoasnfa76pfcZLmcfl_Array"]}
    assert RuntimeLayer(Strength.LENIENT).inspect(env_probe(env), state).reason == "webdriver_flag"


def test_l4_platform_ua_mismatch(state):
    """UA 说是 Windows，platform 却是 Linux —— 单属性伪造最典型的破绽。"""
    env = {**GOOD_ENV, "platform": "Linux x86_64"}
    verdict = RuntimeLayer(Strength.STRICT).inspect(env_probe(env), state)
    assert verdict.reason == "navigator_inconsistent"
    assert verdict.detail["field"] == "platform"


def test_l4_software_renderer(state):
    env = {**GOOD_ENV, "webglRenderer": "Google SwiftShader"}
    assert RuntimeLayer(Strength.PARANOID).inspect(env_probe(env), state).reason == "webgl_mismatch"


def test_l4_apple_gpu_on_windows(state):
    env = {**GOOD_ENV, "webglVendor": "Apple", "webglRenderer": "Apple M2"}
    verdict = RuntimeLayer(Strength.PARANOID).inspect(env_probe(env), state)
    assert verdict.reason == "webgl_mismatch"


def test_l4_degenerate_canvas(state):
    env = {**GOOD_ENV, "canvasHash": "0"}
    assert RuntimeLayer(Strength.PARANOID).inspect(env_probe(env), state).reason == "canvas_suspicious"


def test_l4_implausible_timing(state):
    env = {**GOOD_ENV, "collectMs": 0}
    assert RuntimeLayer(Strength.PARANOID).inspect(env_probe(env), state).reason == "env_timing_implausible"


def test_l4_strict_ignores_webgl(state):
    """strict 档不查 WebGL —— 确认强度档之间的边界是清晰的。"""
    env = {**GOOD_ENV, "webglRenderer": "Google SwiftShader"}
    assert RuntimeLayer(Strength.STRICT).inspect(env_probe(env), state).passed


# --- L5 行为层 ---


def human_trace() -> list[dict]:
    """类人轨迹。

    三个特征缺一不可，否则过不了 paranoid 档：
      间隔不等          -> interval_cv ≈ 0.84
      速度先加后减       -> speed_cv    ≈ 0.73  （最小抖动模型的典型形状）
      路径是弧线不是直线 -> straightness ≈ 0.96

    注意速度剖面必须与时间间隔**不相关**。最初的版本让位移与间隔成正比，
    结果间隔很抖但速度是匀的，照样被 path_unnatural 抓住——这本身就说明
    "间隔加随机 sleep"骗不过速度判据。
    """
    gaps = [18.0, 31.0, 12.0, 44.0, 21.0, 9.0, 37.0, 26.0, 15.0, 40.0, 23.0, 11.0]
    speeds = [0.3, 0.9, 2.1, 3.0, 3.4, 3.1, 2.2, 1.3, 0.7, 0.4, 0.25, 0.15]
    curve = [0.55, 0.45, 0.30, 0.15, 0.0, -0.18, -0.32, -0.42, -0.5, -0.55, -0.6, -0.6]

    events: list[dict] = []
    t, x, y = 0.0, 100.0, 200.0
    for gap, speed, c in zip(gaps, speeds, curve):
        dist = gap * speed
        t += gap
        x += dist
        y += dist * c
        events.append({"t": round(t, 2), "type": "mousemove", "x": round(x), "y": round(y)})
    for type_, gap in (("mousedown", 80.0), ("mouseup", 95.0), ("click", 3.0)):
        t += gap
        events.append({"t": round(t, 2), "type": type_, "x": round(x), "y": round(y)})
    return events


def robot_trace() -> list[dict]:
    """固定 sleep + 直线匀速位移。"""
    events = []
    for i in range(12):
        events.append({"t": i * 20.0, "type": "mousemove", "x": 100 + i * 10, "y": 200 + i * 5})
    for j, type_ in enumerate(("mousedown", "mouseup", "click"), start=12):
        events.append({"t": j * 20.0, "type": type_, "x": 210, "y": 255})
    return events


def trace_probe(events: list[dict]) -> Probe:
    return make_probe(headers={"X-BW-Trace": b64(events)})


def test_l5_human_trace_passes(state):
    assert BehaviorLayer(Strength.PARANOID).inspect(trace_probe(human_trace()), state).passed


def test_l5_robot_trace_caught_by_intervals(state):
    verdict = BehaviorLayer(Strength.STRICT).inspect(trace_probe(robot_trace()), state)
    assert verdict.reason == "interval_variance_low"
    assert verdict.ladder_rung == 5


def test_l5_robot_trace_passes_lenient(state):
    """lenient 只查事件序列完整性，机器轨迹能过 —— 强度档的边界。"""
    assert BehaviorLayer(Strength.LENIENT).inspect(trace_probe(robot_trace()), state).passed


def test_l5_missing_trace(state):
    assert BehaviorLayer(Strength.LENIENT).inspect(make_probe(), state).reason == "trace_missing"


def test_l5_incomplete_sequence(state):
    """只有 click，没有前置的 mousemove/mousedown。"""
    events = [{"t": i * 17.0, "type": "click", "x": 10, "y": 10} for i in range(10)]
    verdict = BehaviorLayer(Strength.LENIENT).inspect(trace_probe(events), state)
    assert verdict.reason == "event_sequence_incomplete"


def test_l5_jittered_sleep_is_not_enough(state):
    """只给 sleep 加随机抖动，骗不过速度判据。

    这是攻击侧最常见的第一反应，也是最常见的误判：以为"间隔随机化"就等于
    像人。但如果位移与间隔成正比（走固定距离、随机等待），速度反而是恒定的，
    paranoid 档照样抓得到。要过这一关必须实现真正的加减速剖面——成本高得多。

    这条测试来自本仓库自己的一次夹具错误，保留它作为回归。
    """
    gaps = [18.0, 31.0, 12.0, 44.0, 21.0, 9.0, 37.0, 26.0, 15.0, 40.0, 23.0, 11.0]
    events = []
    t, x, y = 0.0, 100.0, 200.0
    for gap in gaps:
        t += gap
        x += gap * 2.0  # 位移与间隔成正比 => 速度恒定
        y += gap * 0.5
        events.append({"t": round(t, 2), "type": "mousemove", "x": round(x), "y": round(y)})
    for type_, gap in (("mousedown", 80.0), ("mouseup", 95.0), ("click", 3.0)):
        t += gap
        events.append({"t": round(t, 2), "type": type_, "x": round(x), "y": round(y)})

    # 间隔判据过了
    assert BehaviorLayer(Strength.STRICT).inspect(trace_probe(events), state).passed
    # 速度判据没过
    verdict = BehaviorLayer(Strength.PARANOID).inspect(trace_probe(events), state)
    assert verdict.reason == "path_unnatural"


def test_l5_straight_line_caught_at_paranoid(state):
    """间隔有抖动但路径是完美直线且匀速 —— 只有 paranoid 档抓得到。"""
    events = []
    t, x, y = 0.0, 0.0, 0.0
    for gap in [18.0, 31.0, 12.0, 44.0, 21.0, 9.0, 37.0, 26.0]:
        t += gap
        x += gap * 2  # 严格匀速：位移与时间成正比
        y += gap * 2
        events.append({"t": t, "type": "mousemove", "x": round(x), "y": round(y)})
    for type_, gap in (("mousedown", 70.0), ("mouseup", 90.0), ("click", 4.0)):
        t += gap
        events.append({"t": t, "type": type_, "x": round(x), "y": round(y)})
    assert BehaviorLayer(Strength.STRICT).inspect(trace_probe(events), state).passed
    verdict = BehaviorLayer(Strength.PARANOID).inspect(trace_probe(events), state)
    assert verdict.reason == "path_unnatural"


# --- L6 验证码层 ---


def test_l6_pow_roundtrip(state):
    layer = CaptchaLayer(Strength.LENIENT, {"kind": "pow", "pow_difficulty": 8})
    challenge = layer.issue_challenge("sess1", state)
    assert "prefix" in challenge

    solution = None
    for i in range(1_000_000):
        candidate = str(i)
        digest = hashlib.sha256((challenge["prefix"] + candidate).encode()).digest()
        if 256 - int.from_bytes(digest, "big").bit_length() >= 8:
            solution = candidate
            break
    assert solution is not None

    probe = make_probe(cookies={"bw_session": "sess1"}, headers={"X-BW-Captcha": solution})
    assert layer.inspect(probe, state).passed
    # 一题一用：通过后挑战作废
    assert layer.inspect(probe, state).reason == "captcha_required"


def test_l6_requires_challenge_first(state):
    layer = CaptchaLayer(Strength.LENIENT, {"kind": "pow"})
    probe = make_probe(cookies={"bw_session": "s"}, headers={"X-BW-Captcha": "x"})
    assert layer.inspect(probe, state).reason == "captcha_required"


def test_l6_slider_needs_position_and_trace(state):
    layer = CaptchaLayer(Strength.STRICT, {"kind": "slider", "slider_tolerance": 5})
    public = layer.issue_challenge("s", state)
    assert "gap_x" not in public  # 答案不外泄
    gap = state.pending_challenges["s"]["gap_x"]

    # 位置对但轨迹是机器的
    probe = make_probe(
        cookies={"bw_session": "s"},
        headers={"X-BW-Captcha": str(gap), "X-BW-Trace": b64(robot_trace())},
    )
    assert layer.inspect(probe, state).reason == "captcha_failed"

    # 位置对且轨迹像人
    layer.issue_challenge("s", state)
    gap = state.pending_challenges["s"]["gap_x"]
    probe = make_probe(
        cookies={"bw_session": "s"},
        headers={"X-BW-Captcha": str(gap), "X-BW-Trace": b64(human_trace())},
    )
    assert layer.inspect(probe, state).passed


def test_l6_static_image_not_implemented(state):
    layer = CaptchaLayer(Strength.LENIENT, {"kind": "static_image"})
    with pytest.raises(NotImplementedError):
        layer.issue_challenge("s", state)


# --- Gate ---


def test_gate_form_stops_at_first_failure(state):
    layers = [
        NetworkLayer(Strength.STRICT, {"max_requests": 100}),
        ProtocolLayer(Strength.STRICT, {"salt_mode": "derived", "seed": "s"}),
    ]
    gate = Gate(layers, form="gate")
    result = gate.evaluate(make_probe(client_ip="3.1.2.3"), state)
    assert not result.allowed
    # gate 形态下 L1 失败即返回，L3 根本没跑
    assert [v.layer for v in result.verdicts] == ["l1_network"]
    assert result.required_rung == 2


def test_score_form_accumulates(state):
    """评分形态下单层失败可被补偿 —— 这正是它难归因的原因。"""
    layers = [
        NetworkLayer(Strength.STRICT, {"max_requests": 100, "datacenter_score": 0.5}),
        ProtocolLayer(Strength.STRICT, {"salt_mode": "derived", "seed": "s", "score": 0.4}),
    ]
    gate = Gate(layers, form="score", score_threshold=1.0)
    probe = make_probe(client_ip="3.1.2.3")
    probe = make_probe(client_ip="3.1.2.3", headers=signed_headers(probe))
    result = gate.evaluate(probe, state)
    # L1 扣 0.5，L3 通过，累计 0.5 < 1.0
    assert result.allowed
    assert result.total_score == pytest.approx(0.5)
    assert len(result.verdicts) == 2


def test_captcha_only_triggers_above_threshold(state):
    """验证码是失败模式不是关卡：前面都干净就根本不出题。"""
    layers = [
        NetworkLayer(Strength.STRICT, {"max_requests": 100}),
        CaptchaLayer(Strength.LENIENT, {"kind": "pow"}),
    ]
    gate = Gate(layers, form="score", score_threshold=1.0, captcha_trigger_score=0.5)

    clean = gate.evaluate(make_probe(client_ip="127.0.0.1", cookies={"bw_session": "s"}), state)
    assert clean.allowed
    assert "l6_captcha" not in [v.layer for v in clean.verdicts]

    dirty = gate.evaluate(
        make_probe(client_ip="3.1.2.3", cookies={"bw_session": "s"}), RangeState()
    )
    assert not dirty.allowed
    assert "l6_captcha" in [v.layer for v in dirty.verdicts]
    assert dirty.challenge is not None


def test_diagnostic_body_carries_attribution(state):
    gate = Gate([NetworkLayer(Strength.STRICT, {"max_requests": 100})], form="gate")
    body = gate.evaluate(make_probe(client_ip="3.1.2.3"), state).diagnostic_body()
    assert body["blocked_by"][0]["layer"] == "l1_network"
    assert body["blocked_by"][0]["reason"] == "datacenter_asn"
    assert body["required_ladder_rung"] == 2
