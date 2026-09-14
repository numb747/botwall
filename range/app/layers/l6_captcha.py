"""L6 验证码层 —— 一道显式的题目。

本层在默认 profile 里是关闭的，而且位置在最后。这是刻意的设计表达：

    在现代站点上，验证码不是常规关卡，而是**失败模式**。L1–L5 中某一层已经
    对你产生了怀疑，系统才用一道题来惩罚你。你看到验证码，说明你在前面某层
    已经露馅了。

因此本层的触发条件不是"每次请求都出题"，而是前五层的累计风险分超过阈值。
这个结构让"不触发挑战"成为一个可测量的目标，而不是一句口号。

触发逻辑不在本层内部——本层只负责出题与判题，是否调用它由 gate 决定
（见 app/gate.py）。这保持了"每层只检验一个维度"的约束。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any, ClassVar

from ..core import Probe, RangeState, Strength, Verdict
from .base import Layer
from .l5_behavior import _coefficient_of_variation, _intervals, _path_straightness

#: 支持的题型。static_image 的图像渲染尚未实现，见下方 issue_challenge。
KINDS = ("pow", "slider", "static_image")


class CaptchaLayer(Layer):
    id: ClassVar[str] = "l6_captcha"
    name: ClassVar[str] = "验证码层"
    ladder_rung: ClassVar[int] = 5

    def __init__(self, strength: Strength, options: dict | None = None) -> None:
        super().__init__(strength, options)
        self.kind: str = self.opt("kind", "pow")
        if self.kind not in KINDS:
            raise ValueError(f"{self.id}: 未知题型 {self.kind!r}，可用: {KINDS}")

    # --- 出题 ---

    def issue_challenge(self, session: str, state: RangeState) -> dict[str, Any]:
        """生成一道题并登记到 RangeState，返回给客户端的描述。"""
        if self.kind == "pow":
            difficulty = int(self.opt("pow_difficulty", 18))
            challenge = {
                "kind": "pow",
                "id": secrets.token_hex(8),
                "prefix": secrets.token_hex(12),
                # 要求 sha256(prefix + solution) 的前 difficulty 位为 0
                "difficulty_bits": difficulty,
            }
        elif self.kind == "slider":
            # 滑块的安全性不在图像里，在缺口位置 + 轨迹质量。v0 用 JSON 描述
            # 代替图像渲染：图像是呈现层，不是安全层。
            challenge = {
                "kind": "slider",
                "id": secrets.token_hex(8),
                "track_width": 300,
                "gap_x": secrets.randbelow(200) + 60,
                "tolerance": int(self.opt("slider_tolerance", 5)),
            }
        else:  # static_image
            raise NotImplementedError(
                "static_image 题型尚未实现（需要图像渲染依赖）。"
                "保留该题型是为了如实反映：这类验证码在面向消费者的大流量站点"
                "已基本绝迹，但在政企与传统行业后台仍大量存在。"
            )

        state.pending_challenges[session] = challenge
        # 返回给客户端的副本里去掉答案
        public = dict(challenge)
        if self.kind == "slider":
            public.pop("gap_x", None)
        return public

    # --- 判题 ---

    def inspect(self, probe: Probe, state: RangeState) -> Verdict:
        session = probe.cookies.get("cl_session") or probe.header("x-cl-session")
        if not session:
            return self._fail("captcha_required", detail_note="缺少会话标识，无法关联挑战")

        challenge = state.pending_challenges.get(session)
        if challenge is None:
            return self._fail("captcha_required", detail_note="尚未领取挑战")

        solution = probe.header("x-cl-captcha")
        if not solution:
            return self._fail("captcha_required", challenge_id=challenge["id"])

        if challenge["kind"] == "pow":
            ok, detail = self._verify_pow(challenge, solution)
        else:
            ok, detail = self._verify_slider(challenge, solution, probe)

        if not ok:
            return self._fail("captcha_failed", **detail)

        # 通过后作废，防止一题多用
        state.pending_challenges.pop(session, None)
        state.session_risk[session] = 0.0
        return self._ok(kind=challenge["kind"], **detail)

    def _verify_pow(self, challenge: dict[str, Any], solution: str) -> tuple[bool, dict]:
        digest = hashlib.sha256((challenge["prefix"] + solution).encode()).digest()
        bits = int.from_bytes(digest, "big").bit_length()
        leading_zeros = 256 - bits
        required = challenge["difficulty_bits"]
        return leading_zeros >= required, {
            "leading_zeros": leading_zeros,
            "required_bits": required,
        }

    def _verify_slider(
        self, challenge: dict[str, Any], solution: str, probe: Probe
    ) -> tuple[bool, dict]:
        try:
            submitted_x = float(solution)
        except ValueError:
            return False, {"detail_note": "滑块答案非数值", "value": solution}

        delta = abs(submitted_x - challenge["gap_x"])
        if delta > challenge["tolerance"]:
            return False, {"position_delta": round(delta, 2), "tolerance": challenge["tolerance"]}

        # 位置对了还不够：轨迹质量同样参与判定。复用 L5 的判据——
        # 这是唯一允许的层间复用，因为滑块的轨迹检验在概念上就是 L5 的子集。
        if self.strength.at_least(Strength.STRICT):
            trace = self._decode_trace(probe)
            if trace is None:
                return False, {"detail_note": "滑块缺少轨迹"}
            if len(trace) < 5:
                return False, {"detail_note": "轨迹采样点不足", "observed": len(trace)}
            cv = _coefficient_of_variation(_intervals(trace))
            if cv < float(self.opt("min_interval_cv", 0.25)):
                return False, {"detail_note": "轨迹间隔过于均匀", "interval_cv": round(cv, 4)}
            points = [(float(e["x"]), float(e["y"])) for e in trace if "x" in e and "y" in e]
            if len(points) >= 3:
                straightness = _path_straightness(points)
                if straightness > float(self.opt("max_straightness", 0.99)):
                    return False, {
                        "detail_note": "轨迹接近完美直线",
                        "straightness": round(straightness, 4),
                    }

        return True, {"position_delta": round(delta, 2)}

    @staticmethod
    def _decode_trace(probe: Probe) -> list[dict] | None:
        import base64
        import binascii
        import json

        raw = probe.header("x-cl-trace")
        if not raw:
            return None
        try:
            trace = json.loads(base64.b64decode(raw, validate=True))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return None
        return trace if isinstance(trace, list) else None


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
