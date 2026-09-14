"""L4 运行时层 —— 只看客户端 JS 运行时环境的**自洽性**。

这一层不问"你是不是浏览器"（没法问），而是问"你声称的这套环境属性之间
有没有互相矛盾"。伪造单个属性很容易，让几十个属性互相自洽很难——
这是环境检测的全部要义。

被本层拦住意味着需要一个真实的 JS 运行时环境，而不只是执行一段算法。
对应成本阶梯上从轻量 JS 引擎升级到完整无头浏览器 + 指纹补丁。
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any, ClassVar

from ..core import Probe, RangeState, Strength, Verdict
from .base import Layer
from .l2_transport import ua_family

#: UA 中的操作系统标记 -> navigator.platform 的合法取值。
_UA_OS_TO_PLATFORMS: dict[str, tuple[str, ...]] = {
    "windows": ("Win32", "Win64"),
    "macintosh": ("MacIntel",),
    "iphone": ("iPhone",),
    "ipad": ("iPad", "MacIntel"),
    "android": ("Linux armv8l", "Linux aarch64", "Linux armv7l"),
    "linux": ("Linux x86_64", "Linux i686"),
}

#: WebGL vendor 与操作系统的合理组合。Apple 的 GPU 字符串不可能出现在 Windows 上。
_WEBGL_VENDOR_OS: dict[str, tuple[str, ...]] = {
    "apple": ("macintosh", "iphone", "ipad"),
    "google inc.": ("windows", "macintosh", "linux", "android"),  # SwiftShader/ANGLE
    "intel inc.": ("windows", "macintosh", "linux"),
    "nvidia corporation": ("windows", "linux"),
    "amd": ("windows", "linux"),
    "qualcomm": ("android",),
    "arm": ("android",),
}

#: 已知的无头/软件渲染标志。出现即强信号。
_HEADLESS_RENDERER_MARKERS = ("swiftshader", "llvmpipe", "mesa offscreen", "headless")

#: 全零、全相同或过短的 canvas 指纹，通常意味着 canvas 被 stub 掉了。
_DEGENERATE_CANVAS = {"", "0", "00000000", "null", "undefined"}


def _ua_os(user_agent: str) -> str | None:
    ua = user_agent.lower()
    # 顺序有意义：iPad 的 UA 可能同时含 Macintosh
    for marker in ("iphone", "ipad", "android", "windows", "macintosh", "linux"):
        if marker in ua:
            return marker
    return None


class RuntimeLayer(Layer):
    id: ClassVar[str] = "l4_runtime"
    name: ClassVar[str] = "运行时层"
    ladder_rung: ClassVar[int] = 4  # 被拦 -> 需要完整浏览器，即阶梯 L4

    def inspect(self, probe: Probe, state: RangeState) -> Verdict:
        raw = probe.header("x-cl-env")
        if not raw:
            return self._fail("env_missing", score=float(self.opt("missing_score", 1.0)))

        try:
            env = json.loads(base64.b64decode(raw, validate=True))
        except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
            return self._fail("env_malformed", detail_error=str(exc))
        if not isinstance(env, dict):
            return self._fail("env_malformed", detail_error="顶层不是对象")

        # --- lenient：只查显式自动化标志 ---
        flags = [
            key
            for key in ("webdriver", "_phantom", "callPhantom", "__nightmare", "__selenium_unwrapped")
            if env.get(key)
        ]
        cdp_keys = [k for k in env.get("windowKeys", []) if str(k).startswith("cdc_")]
        if flags or cdp_keys:
            return self._fail(
                "webdriver_flag",
                score=float(self.opt("automation_score", 1.0)),
                flags=flags,
                cdp_residue=cdp_keys[:5],
            )

        if self.strength is Strength.LENIENT:
            return self._ok(checked="automation_flags_only")

        # --- strict：navigator 属性组交叉一致性 ---
        ua = str(env.get("userAgent", ""))
        if ua != probe.header("user-agent"):
            return self._fail(
                "ua_header_env_mismatch",
                header_ua=probe.header("user-agent"),
                env_ua=ua,
            )

        os_marker = _ua_os(ua)
        platform = str(env.get("platform", ""))
        if os_marker and platform:
            allowed = _UA_OS_TO_PLATFORMS.get(os_marker, ())
            if allowed and platform not in allowed:
                return self._fail(
                    "navigator_inconsistent",
                    field="platform",
                    ua_os=os_marker,
                    platform=platform,
                    expected_one_of=list(allowed),
                )

        cores = env.get("hardwareConcurrency")
        if not isinstance(cores, int) or not (1 <= cores <= 256):
            return self._fail("navigator_inconsistent", field="hardwareConcurrency", value=cores)

        languages = env.get("languages")
        if not isinstance(languages, list) or not languages:
            return self._fail("navigator_inconsistent", field="languages", value=languages)

        if ua_family(ua) is None:
            return self._fail("navigator_inconsistent", field="userAgent", value=ua)

        if self.strength is Strength.STRICT:
            return self._ok(checked="navigator_consistency")

        # --- paranoid：WebGL / Canvas 与声明平台的匹配，以及采集耗时 ---
        vendor = str(env.get("webglVendor", "")).strip().lower()
        renderer = str(env.get("webglRenderer", "")).strip().lower()
        if not vendor or not renderer:
            return self._fail("webgl_mismatch", field="missing", vendor=vendor, renderer=renderer)

        marker = next((m for m in _HEADLESS_RENDERER_MARKERS if m in renderer), None)
        if marker:
            return self._fail("webgl_mismatch", reason_detail="软件渲染器", marker=marker)

        if os_marker:
            allowed_os = next(
                (oses for known, oses in _WEBGL_VENDOR_OS.items() if known in vendor), None
            )
            if allowed_os is not None and os_marker not in allowed_os:
                return self._fail(
                    "webgl_mismatch",
                    vendor=vendor,
                    ua_os=os_marker,
                    vendor_expects=list(allowed_os),
                )

        canvas = str(env.get("canvasHash", "")).strip().lower()
        if canvas in _DEGENERATE_CANVAS or len(canvas) < 8:
            return self._fail("canvas_suspicious", canvas_hash=canvas)

        # 环境快照的生成耗时。真实浏览器采集这些属性需要可观察的时间；
        # 伪造的快照往往是常量表，耗时为 0 或被随便填了个数。
        elapsed = env.get("collectMs")
        lo = float(self.opt("collect_ms_min", 0.5))
        hi = float(self.opt("collect_ms_max", 500.0))
        if not isinstance(elapsed, (int, float)) or not (lo <= float(elapsed) <= hi):
            return self._fail(
                "env_timing_implausible", collect_ms=elapsed, expected_range=[lo, hi]
            )

        return self._ok(checked="full", webgl_vendor=vendor)
