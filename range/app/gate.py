"""Gate —— 把六层串成一次完整判定。

两件事在这里决定，而不在层里：

  响应形态 (form)
    gate   任一层失败立即拒绝。归因清晰，适合逐层测量单层成本。
    score  累计风险分超阈值才拒绝，单层失败可被其他层的高保真度补偿。
           更接近真实商业风控，也更难归因——这正是要测的东西。

  响应模式 (mode)
    diagnostic  被拦时明确告知被哪层拦、原因码、诊断细节
    blind       被拦时返回结构合法但内容虚假的数据，不给任何失败信号

blind 模式测量的是采集工程里最贵、也最少被量化的一项成本：排障工时。
见 docs/03-cost-model.md 的 T_diag。

L6 的触发也在这里：它不是常规关卡，只在前五层累计风险分超阈值时才出题。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .core import Probe, RangeState, Verdict
from .layers import CaptchaLayer, Layer


@dataclass
class GateResult:
    allowed: bool
    verdicts: list[Verdict] = field(default_factory=list)
    total_score: float = 0.0
    #: 被拦时，建议爬到的成本阶梯级号；通过时为 0
    required_rung: int = 0
    #: 需要先解一道题时的挑战描述
    challenge: dict[str, Any] | None = None

    @property
    def blocking(self) -> list[Verdict]:
        return [v for v in self.verdicts if not v.passed]

    def diagnostic_body(self) -> dict[str, Any]:
        """diagnostic 模式下返回给客户端的归因信息。"""
        return {
            "allowed": self.allowed,
            "required_ladder_rung": self.required_rung,
            "total_score": round(self.total_score, 3),
            "blocked_by": [
                {
                    "layer": v.layer,
                    "reason": v.reason,
                    "score": v.score,
                    "ladder_rung": v.ladder_rung,
                    "detail": v.detail,
                }
                for v in self.blocking
            ],
            "passed_layers": [v.layer for v in self.verdicts if v.passed],
        }


class Gate:
    def __init__(
        self,
        layers: list[Layer],
        *,
        form: str = "gate",
        mode: str = "diagnostic",
        score_threshold: float = 1.0,
        captcha_trigger_score: float = 1.0,
    ) -> None:
        if form not in ("gate", "score"):
            raise ValueError(f"未知的 form: {form!r}")
        if mode not in ("diagnostic", "blind"):
            raise ValueError(f"未知的 mode: {mode!r}")
        self.form = form
        self.mode = mode
        self.score_threshold = score_threshold
        self.captcha_trigger_score = captcha_trigger_score
        # L6 单独拿出来，因为它的调用条件由累计分决定，不与前五层同列
        self.captcha: CaptchaLayer | None = next(
            (layer for layer in layers if isinstance(layer, CaptchaLayer)), None
        )
        self.layers = [layer for layer in layers if not isinstance(layer, CaptchaLayer)]

    def evaluate(self, probe: Probe, state: RangeState) -> GateResult:
        result = GateResult(allowed=True)

        for layer in self.layers:
            verdict = layer.inspect(probe, state)
            result.verdicts.append(verdict)
            if verdict.passed:
                continue
            result.total_score += verdict.score
            result.required_rung = max(result.required_rung, verdict.ladder_rung)
            if self.form == "gate":
                result.allowed = False
                return result

        if self.form == "score" and result.total_score >= self.score_threshold:
            result.allowed = False

        # L6：只在前五层累计出足够怀疑时才出题。
        # 注意这里的顺序——先判定是否触发，再判题。没触发就根本不问。
        if self.captcha is not None and result.total_score >= self.captcha_trigger_score:
            verdict = self.captcha.inspect(probe, state)
            result.verdicts.append(verdict)
            if verdict.passed:
                # 题答对了，抵消前面累计的怀疑
                result.allowed = True
                result.total_score = 0.0
                result.required_rung = 0
            else:
                result.allowed = False
                result.required_rung = max(result.required_rung, verdict.ladder_rung)
                if verdict.reason == "captcha_required":
                    session = probe.cookies.get("cl_session") or probe.header("x-cl-session")
                    if session:
                        result.challenge = self.captcha.issue_challenge(session, state)

        return result
