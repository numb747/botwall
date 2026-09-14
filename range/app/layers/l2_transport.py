"""L2 传输层 —— 只看 TLS / HTTP2 握手指纹，与应用层完全无关。

被本层拦住意味着 HTTP 客户端选型不对，对应成本阶梯上换一个具备指纹伪装能力
的客户端。这一跳的成本增量几乎为零——换个库而已——所以它是整条阶梯上性价比
最高的一级，也是最容易被误判的一级：很多人在这里被拦却以为"要上浏览器"，
直接跳到阶梯 L4，白白付出约 50 倍成本。

指纹从哪来
----------
TLS 指纹在应用层拿不到，需要前置的 tlsfront 代理解析 ClientHello 原始字节、
计算 JA3，再以 X-BW-JA3 头转发。纯 HTTP 的本地开发模式下该头可被客户端伪造,
这是有意为之，便于单测；启用 tlsfront 后代理会强制覆盖该头。

指纹名单来自 profile 引用的指纹集（range/fingerprints/*.yaml）。仓库内置的
demo 指纹集是占位值，不是真实浏览器的 JA3——真实值需要用 tlsfront 从自己的
浏览器录制。在指纹集被填充为真值之前，本层的测量结果不具备对外可比性。
"""

from __future__ import annotations

import re
from typing import ClassVar

from ..core import Probe, RangeState, Strength, Verdict
from .base import Layer

#: UA 里的浏览器族识别。顺序有意义：Edg 必须在 Chrome 之前，
#: 因为 Edge 的 UA 同时含有 "Chrome"。
_UA_FAMILY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("edge", re.compile(r"Edg/", re.I)),
    ("opera", re.compile(r"OPR/", re.I)),
    ("chrome", re.compile(r"Chrome/", re.I)),
    ("firefox", re.compile(r"Firefox/", re.I)),
    ("safari", re.compile(r"Safari/", re.I)),
)


def ua_family(user_agent: str) -> str | None:
    for family, pattern in _UA_FAMILY_PATTERNS:
        if pattern.search(user_agent):
            return family
    return None


class TransportLayer(Layer):
    id: ClassVar[str] = "l2_transport"
    name: ClassVar[str] = "传输层"
    ladder_rung: ClassVar[int] = 0  # 被拦 -> 换个 HTTP 客户端，不离开阶梯 L0

    def __init__(self, strength: Strength, options: dict | None = None) -> None:
        super().__init__(strength, options)
        fp = self.opt("fingerprints", {}) or {}
        #: ja3 -> 客户端名，用于"这明显是脚本库"的判定
        self.script_clients: dict[str, str] = dict(fp.get("script_clients", {}))
        #: ja3 -> 浏览器族，用于白名单与交叉一致性判定
        self.browsers: dict[str, str] = dict(fp.get("browsers", {}))

    def inspect(self, probe: Probe, state: RangeState) -> Verdict:
        ja3 = probe.header("x-bw-ja3")
        if not ja3:
            # 没有前置代理、客户端也没自报。lenient 档放行（便于本地开发），
            # 更高档位视为不可验证即拒绝。
            if self.strength is Strength.LENIENT:
                return self._ok(ja3=None, note="缺少指纹，lenient 档放行")
            return self._fail(
                "ja3_absent",
                score=float(self.opt("absent_score", 0.5)),
                hint="需要前置 tlsfront 代理，或在开发模式下自行设置 X-BW-JA3",
            )

        if ja3 in self.script_clients:
            return self._fail(
                "ja3_known_script_client",
                score=float(self.opt("script_client_score", 1.0)),
                ja3=ja3,
                identified_as=self.script_clients[ja3],
            )

        if self.strength.at_least(Strength.STRICT):
            if ja3 not in self.browsers:
                return self._fail(
                    "ja3_not_in_allowlist",
                    score=float(self.opt("allowlist_score", 1.0)),
                    ja3=ja3,
                )

        if self.strength is Strength.PARANOID:
            # 交叉一致性：声称自己是 Chrome，握手却是 Firefox 的形状。
            # 这是强度高得多的信号，因为它无法通过换一个 UA 绕过。
            claimed = ua_family(probe.header("user-agent"))
            actual = self.browsers.get(ja3)
            if claimed is None:
                return self._fail(
                    "ua_family_unknown",
                    score=float(self.opt("mismatch_score", 0.8)),
                    user_agent=probe.header("user-agent"),
                )
            if actual is not None and claimed != actual:
                return self._fail(
                    "ja3_ua_mismatch",
                    score=float(self.opt("mismatch_score", 1.0)),
                    ja3=ja3,
                    ja3_family=actual,
                    ua_family=claimed,
                )

        return self._ok(ja3=ja3, family=self.browsers.get(ja3))
