"""L4 运行时层 —— 判定"你有没有真实的 JS 运行时"。

两种机制，用 options.mechanism 选择：

  env   检查客户端提交的环境快照**自洽不自洽**。伪造单个属性很容易，让几十个
        属性互相自洽很难。但这终究是"校验声明"——手写一份不矛盾的 JSON 就能过
        （harness 里的 enveloped.py 正是这么干的）。保留它有教学价值，也如实
        反映了相当多生产环境的真实强度。

  vm    下发一段**每会话都不同的随机字节码 + 解释它的 JS**，客户端必须执行
        才能算出 token。这是"要求证明"而非"校验声明"——程序每次都变，预先
        逆向无效。见 app/vm.py。

  both  两者都要过。

env 可以纯靠构造 JSON 骗过，vm 不行。这个区别是本层强弱的分水岭，也是真实
防御（瑞数五代、acw_sc__v2、a_bogus 那一类）与朴素指纹校验的分水岭。

被本层拦住意味着需要一个真实的 JS 运行时，对应成本阶梯上从纯 HTTP 升级到
至少要带一个 JS 引擎。
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from typing import Any, ClassVar

from .. import vm
from ..core import Probe, RangeState, Strength, Verdict
from .base import Layer
from .l2_transport import ua_family

#: 各强度档下 VM 程序的长度与是否打乱操作码。
#: lenient  攻击方写一次 VM 模拟器就能一劳永逸（现实中被攻破的状态）
#: strict   操作码逐会话打乱，模拟器每次失效
#: paranoid 更长的程序，执行成本也更高
_VM_PROFILE: dict[Strength, tuple[int, bool]] = {
    Strength.LENIENT: (64, False),
    Strength.STRICT: (160, True),
    Strength.PARANOID: (400, True),
}

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

    @property
    def mechanism(self) -> str:
        value = self.opt("mechanism", "env")
        if value not in ("env", "vm", "both"):
            raise ValueError(f"{self.id}: 未知的 mechanism {value!r}")
        return value

    def challenge_for(self, session: str) -> vm.Challenge:
        """本会话的 VM 挑战。

        完全由 seed 派生，所以服务端**不存任何状态**就能在校验时复算出同一段
        程序。这也是靶场可复现性的要求：同一个 session 在任何机器上拿到同一段
        字节码。
        """
        length, shuffle = _VM_PROFILE[self.strength]
        seed = f"{self.opt('vm_seed', 'cl-vm')}::{session}"
        return vm.build_challenge(seed, length=length, shuffle_opcodes=shuffle)

    def inspect(self, probe: Probe, state: RangeState) -> Verdict:
        mechanism = self.mechanism
        if mechanism in ("vm", "both"):
            verdict = self._inspect_vm(probe)
            if not verdict.passed:
                return verdict
            if mechanism == "vm":
                return verdict
        return self._inspect_env(probe)

    # --- vm 机制：要求客户端执行现场下发的字节码 ---

    def _inspect_vm(self, probe: Probe) -> Verdict:
        session = probe.cookies.get("cl_session") or probe.header("x-cl-session")
        if not session:
            return self._fail(
                "vm_session_missing",
                score=float(self.opt("missing_score", 1.0)),
                hint="VM 挑战按会话派生，需要 cl_session cookie 或 X-CL-Session 头",
            )

        submitted = probe.header("x-cl-vm")
        if not submitted:
            return self._fail(
                "vm_token_missing",
                score=float(self.opt("missing_score", 1.0)),
                hint="先取 /api/vm-challenge，在真实 JS 运行时里执行后提交 X-CL-VM",
            )

        # ts 与 nonce 在这里只作为 VM 的输入，不做时效判定——那是 L3 的维度，
        # 本层不重复判断。它们进输入是为了让**每个请求**都必须跑一次 VM。
        try:
            ts_ms = int(probe.header("x-cl-ts") or "0")
        except ValueError:
            return self._fail("vm_input_malformed", field="X-CL-Ts")
        nonce = probe.header("x-cl-nonce")

        challenge = self.challenge_for(session)
        inputs = vm.make_inputs(vm.seed32_of(challenge.seed), ts_ms, nonce)
        expected = vm.token_hex(vm.execute(challenge, inputs))

        if not hmac.compare_digest(expected, submitted.strip().lower()):
            detail: dict[str, Any] = {"program_length": challenge.length}
            if self.strength is Strength.LENIENT:
                # lenient 是教学档：回显期望值，先跑通链路再关掉它去真正实现 VM
                detail["expected"] = expected
                detail["inputs"] = inputs
            return self._fail("vm_token_mismatch", score=float(self.opt("score", 1.0)), **detail)

        return self._ok(mechanism="vm", program_length=challenge.length)

    # --- env 机制：检查环境快照自洽性 ---

    def _inspect_env(self, probe: Probe) -> Verdict:
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
