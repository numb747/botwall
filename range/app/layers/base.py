"""层基类与注册表。

新增一层只需要：继承 Layer、声明 id / ladder_rung、实现 inspect，然后在
LAYER_REGISTRY 里登记。层之间不允许互相 import。
"""

from __future__ import annotations

import abc
from typing import Any, ClassVar

from ..core import Probe, RangeState, Strength, Verdict


class Layer(abc.ABC):
    """一层防御。

    契约：
      - 只检验一个维度，不顺带检验别的（有重叠就归因不了）
      - inspect 必须是纯判定，不修改请求，只允许写 RangeState 里属于自己的部分
      - 失败时必须给出 reason
    """

    id: ClassVar[str]
    name: ClassVar[str]
    #: 被本层拦住，至少要爬到成本阶梯的第几级
    ladder_rung: ClassVar[int]

    def __init__(self, strength: Strength, options: dict[str, Any] | None = None) -> None:
        if strength is Strength.OFF:
            raise ValueError(f"{self.id}: off 档的层不应被实例化")
        self.strength = strength
        self.options = options or {}

    def opt(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    @abc.abstractmethod
    def inspect(self, probe: Probe, state: RangeState) -> Verdict:
        ...

    # --- 便利构造 ---

    def _ok(self, **detail: Any) -> Verdict:
        return Verdict(layer=self.id, passed=True, detail=detail, ladder_rung=self.ladder_rung)

    def _fail(self, reason: str, score: float = 1.0, **detail: Any) -> Verdict:
        return Verdict(
            layer=self.id,
            passed=False,
            score=score,
            reason=reason,
            detail=detail,
            ladder_rung=self.ladder_rung,
        )


def build_layers(layer_config: dict[str, dict[str, Any]]) -> list[Layer]:
    """按 profile 配置实例化启用的层，按 id 排序返回。"""
    from . import LAYER_REGISTRY

    layers: list[Layer] = []
    for layer_id, cfg in layer_config.items():
        if layer_id not in LAYER_REGISTRY:
            raise KeyError(f"未知的层: {layer_id}；可用: {sorted(LAYER_REGISTRY)}")
        strength = Strength(cfg.get("strength", "off"))
        if strength is Strength.OFF:
            continue
        layers.append(LAYER_REGISTRY[layer_id](strength, cfg.get("options", {})))
    layers.sort(key=lambda layer: layer.id)
    return layers
