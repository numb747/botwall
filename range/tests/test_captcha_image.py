"""图片验证码的测试。

这一层和别的层不同：它**不是**要证明防御有多强，而是要如实呈现它有多弱。
所以测试里有一条是专门断言"标签可以被无限量免费导出"的——那是这个范式的
结构性死穴，不该被藏起来。
"""

from __future__ import annotations

import io

import pytest

from app import captcha_image as ci
from app.core import RangeState, Strength
from app.layers import CaptchaLayer

PIL = pytest.importorskip("PIL", reason="需要 Pillow")
from PIL import Image  # noqa: E402


# --- 标签的确定性（安全性只依赖它）---


def test_label_is_deterministic():
    """标签由 seed 密码学派生，服务端据此无状态校验。"""
    assert ci.derive_text("s1") == ci.derive_text("s1")


def test_label_differs_per_seed():
    labels = {ci.derive_text(f"s{i}") for i in range(50)}
    assert len(labels) > 45, f"标签碰撞过多: {len(labels)}/50"


def test_label_length_respected():
    for length in (4, 5, 6, 8):
        assert len(ci.derive_text("s", length)) == length


def test_charset_excludes_lookalikes():
    """0/O、1/l/I、2/Z、5/S 必须排除 —— 它们抬高人类误读率远多于抬高机器难度。"""
    for char in "01OIlZS2":
        assert char not in ci.CHARSET, f"形近字符 {char!r} 不该出现在字符集里"


def test_label_only_uses_charset():
    for index in range(30):
        assert set(ci.derive_text(f"s{index}", 8)) <= set(ci.CHARSET)


# --- 渲染 ---


@pytest.mark.parametrize("difficulty", ["lenient", "strict", "paranoid"])
def test_renders_valid_png(difficulty):
    challenge = ci.generate("seed", difficulty=difficulty)
    image = Image.open(io.BytesIO(challenge.png))
    assert image.format == "PNG"
    assert image.size == (ci.WIDTH, ci.HEIGHT)


def test_unknown_difficulty_rejected():
    with pytest.raises(ValueError):
        ci.generate("seed", difficulty="impossible")


def test_higher_difficulty_adds_entropy():
    """难度越高图像越复杂 —— 用 PNG 体积作代理指标。"""
    sizes = {d: len(ci.generate("seed", difficulty=d).png) for d in ("lenient", "strict", "paranoid")}
    assert sizes["lenient"] < sizes["strict"] < sizes["paranoid"], sizes


def test_same_seed_same_pixels():
    """像素级可复现不是安全属性，但它让靶场的回归测试成为可能。"""
    assert ci.generate("s", difficulty="paranoid").png == ci.generate("s", difficulty="paranoid").png


# --- 比对 ---


def test_answer_is_case_insensitive():
    challenge = ci.generate("s")
    assert challenge.matches(challenge.text.lower())
    assert challenge.matches(f"  {challenge.text}  ")


def test_wrong_answer_rejected():
    challenge = ci.generate("s")
    assert not challenge.matches("ZZZZZ")
    assert not challenge.matches("")


# --- 结构性死穴：训练集是免费的 ---


def test_generator_ships_its_own_labels():
    """这个范式为什么死了，一条测试就能说清。

    生成图像的程序同时知道答案，于是攻击方能无限量产出与线上同分布的
    (图像, 标签) 对。加难度不解决这个问题——它只会让人类失败率涨得更快。
    """
    dataset = [ci.generate(f"free::{i}", difficulty="paranoid") for i in range(40)]
    assert all(c.text and c.png for c in dataset)
    # 标签互不相同、直接可用，无需任何标注成本
    assert len({c.text for c in dataset}) > 35


# --- 接入 L6 ---


def test_layer_issues_image_challenge_without_leaking_answer():
    state = RangeState()
    layer = CaptchaLayer(Strength.STRICT, {"kind": "static_image"})
    public = layer.issue_challenge("sess", state)

    assert public["kind"] == "static_image"
    assert public["png_base64"]
    assert "answer" not in public, "答案泄漏给了客户端"
    assert state.pending_challenges["sess"]["answer"]


def test_layer_verifies_image_answer(make_probe):
    state = RangeState()
    layer = CaptchaLayer(Strength.STRICT, {"kind": "static_image"})
    layer.issue_challenge("sess", state)
    answer = state.pending_challenges["sess"]["answer"]

    probe = make_probe(cookies={"bw_session": "sess"}, headers={"X-BW-Captcha": answer.lower()})
    assert layer.inspect(probe, state).passed
    # 一题一用
    assert layer.inspect(probe, state).reason == "captcha_required"


def test_layer_rejects_wrong_image_answer(make_probe):
    state = RangeState()
    layer = CaptchaLayer(Strength.STRICT, {"kind": "static_image"})
    layer.issue_challenge("sess", state)

    probe = make_probe(cookies={"bw_session": "sess"}, headers={"X-BW-Captcha": "WRONG"})
    assert layer.inspect(probe, state).reason == "captcha_failed"


@pytest.mark.parametrize(
    "strength,expected",
    [(Strength.LENIENT, "lenient"), (Strength.STRICT, "strict"), (Strength.PARANOID, "paranoid")],
)
def test_strength_selects_difficulty(strength, expected):
    state = RangeState()
    layer = CaptchaLayer(strength, {"kind": "static_image"})
    assert layer.issue_challenge("s", state)["difficulty"] == expected
