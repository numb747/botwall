"""层注册表。

新增一层：在这里登记即可，profile 里用 id 引用。
"""

from __future__ import annotations

from .base import Layer, build_layers
from .l1_network import NetworkLayer
from .l2_transport import TransportLayer
from .l3_protocol import ProtocolLayer
from .l4_runtime import RuntimeLayer
from .l5_behavior import BehaviorLayer
from .l6_captcha import CaptchaLayer

LAYER_REGISTRY: dict[str, type[Layer]] = {
    NetworkLayer.id: NetworkLayer,
    TransportLayer.id: TransportLayer,
    ProtocolLayer.id: ProtocolLayer,
    RuntimeLayer.id: RuntimeLayer,
    BehaviorLayer.id: BehaviorLayer,
    CaptchaLayer.id: CaptchaLayer,
}

__all__ = [
    "LAYER_REGISTRY",
    "Layer",
    "build_layers",
    "NetworkLayer",
    "TransportLayer",
    "ProtocolLayer",
    "RuntimeLayer",
    "BehaviorLayer",
    "CaptchaLayer",
]
