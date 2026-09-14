"""L3 协议层 —— 请求签名。整条成本阶梯上成本差最大的一道分水岭。

国内主流站点的真实门槛几乎都在这一层，而不在验证码。签名能不能脱离浏览器
静态复现，直接决定你停在阶梯 L1 还是被顶到 L4。

本层在成本模型里的处理方式与其他层不同：它付出的是**一次性逆向工时**，
而非持续的边际成本。逆出来之后单次请求成本和 L0 几乎相同。见 docs/03-cost-model.md。

时效与重放
----------
除签名本身外还校验时间戳新鲜度与 nonce 重放。这两条是刻意加的：它们让
"抓一个包反复重放"这条最廉价的路径失效，逼迫实现方真正复现签名算法——
而这正是签名逆向这门手艺的实际要求。
"""

from __future__ import annotations

import hmac
from typing import ClassVar

from .. import signing
from ..core import Probe, RangeState, Strength, Verdict
from .base import Layer


class ProtocolLayer(Layer):
    id: ClassVar[str] = "l3_protocol"
    name: ClassVar[str] = "协议层"
    ladder_rung: ClassVar[int] = 1  # 被拦 -> 至少要复现签名，即阶梯 L1

    def __init__(self, strength: Strength, options: dict | None = None) -> None:
        super().__init__(strength, options)
        self.salt_mode: str = self.opt("salt_mode", "static")
        if self.salt_mode not in ("static", "derived", "runtime"):
            raise ValueError(f"{self.id}: 未知的 salt_mode {self.salt_mode!r}")
        self.seed: str = self.opt("seed", "cl-demo-seed")
        self.static_salt: str = self.opt("static_salt", "cl-demo-salt")
        self.ts_window: float = float(self.opt("ts_window_seconds", 60.0))

    @property
    def effective_rung(self) -> int:
        """runtime 档把你顶到阶梯 L3（需要 JS 引擎），其余档位停在 L1。"""
        return 3 if self.salt_mode == "runtime" else 1

    def inspect(self, probe: Probe, state: RangeState) -> Verdict:
        rung = self.effective_rung
        ts_raw = probe.header("x-cl-ts")
        nonce = probe.header("x-cl-nonce")
        provided = probe.header("x-cl-sign")

        if not (ts_raw and nonce and provided):
            return self._fail_at(
                rung,
                "sign_missing",
                missing=[
                    name
                    for name, value in (
                        ("X-CL-Ts", ts_raw),
                        ("X-CL-Nonce", nonce),
                        ("X-CL-Sign", provided),
                    )
                    if not value
                ],
            )

        try:
            ts_ms = int(ts_raw)
        except ValueError:
            return self._fail_at(rung, "ts_malformed", value=ts_raw)

        skew = abs(probe.received_at - ts_ms / 1000.0)
        if skew > self.ts_window:
            return self._fail_at(
                rung, "ts_expired", skew_seconds=round(skew, 3), window_seconds=self.ts_window
            )

        if not state.check_and_record_nonce(nonce, probe.received_at):
            return self._fail_at(rung, "nonce_replayed", nonce=nonce)

        expected = signing.compute(
            salt_mode=self.salt_mode,
            seed=self.seed,
            static_salt=self.static_salt,
            env_snapshot=probe.header("x-cl-env"),
            method=probe.method,
            path=probe.path,
            canonical_query=probe.canonical_query,
            ts=ts_raw,
            nonce=nonce,
        )

        if not hmac.compare_digest(expected, provided):
            detail = {"salt_mode": self.salt_mode}
            if self.strength is Strength.LENIENT:
                # lenient 档把期望值也给出来。这不是漏洞，是教学档：
                # 让人先跑通流程，再关掉它去真正逆向。
                detail["expected"] = expected
                detail["signed_payload"] = signing.canonical_payload(
                    probe.method, probe.path, probe.canonical_query, ts_raw, nonce
                )
            return self._fail_at(rung, "sign_mismatch", **detail)

        return self._ok(salt_mode=self.salt_mode, rung=rung)

    def _fail_at(self, rung: int, reason: str, **detail) -> Verdict:
        verdict = self._fail(reason, score=float(self.opt("score", 1.0)), **detail)
        verdict.ladder_rung = rung
        return verdict
