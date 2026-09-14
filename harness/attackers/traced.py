"""L5 · traced —— 合成类人交互轨迹。

在 enveloped 的基础上多提交一条事件轨迹，过 L5 行为层。这是阶梯的顶端。

三个判据必须同时满足，缺一不可
------------------------------
    间隔不等          interval_cv  > 0.30
    速度先加后减       speed_cv     > 0.25
    路径是弧线不是直线  straightness < 0.97

最容易踩的坑：**给 sleep 加随机抖动是不够的。** 如果位移与间隔成正比
（走固定距离、随机等待），间隔的变异系数很高，但速度反而恒定，照样被
path_unnatural 抓住。要过必须实现真正的加减速剖面——也就是最小抖动模型
那种"起步慢、中段快、接近目标减速"的形状。

（靶场的测试套件里有一条 test_l5_jittered_sleep_is_not_enough 专门钉这件事，
它来自本仓库自己的一次夹具错误。）

成本归属
--------
与 enveloped 同理，这一级的成本主要落在 dev_hours 上，边际请求成本只多了
一条轨迹的字节数。**但这一级在真实世界里不是这样**：真实的行为层防御要求
轨迹来自真实浏览器的事件流，合成轨迹会被更强的判据（如与渲染帧率的相关性、
与滚动/焦点事件的耦合）识破，那时就只能真开浏览器，边际成本才会跳到 ~50×。

所以本实现测出来的 L5 成本是**下界**，不是真实成本。这一点在解读结果时
必须讲明，否则会低估行为层防御的效力。
"""

from __future__ import annotations

import base64
import json
import os
import time

from _base import Attacker, main
from enveloped import consistent_env, runtime_salt
from signed import derive_salt, sign
from spoofed import UA

#: 间隔不规则
_GAPS = [18.0, 31.0, 12.0, 44.0, 21.0, 9.0, 37.0, 26.0, 15.0, 40.0, 23.0, 11.0]
#: 速度剖面：起步慢 -> 中段快 -> 接近目标减速。必须与 _GAPS 不相关。
_SPEEDS = [0.3, 0.9, 2.1, 3.0, 3.4, 3.1, 2.2, 1.3, 0.7, 0.4, 0.25, 0.15]
#: 横向偏移系数先正后负，让路径成为弧线而非直线
_CURVE = [0.55, 0.45, 0.30, 0.15, 0.0, -0.18, -0.32, -0.42, -0.5, -0.55, -0.6, -0.6]


def synth_trace(jitter_seed: int = 0) -> str:
    """合成一条类人轨迹。

    jitter_seed 让不同请求的轨迹略有差异 —— 每次都提交逐字节相同的轨迹，
    在真实风控里本身就是个强信号（虽然靶场当前没有检查这一点）。
    """
    rnd = (jitter_seed * 2654435761) % 2**32
    events: list[dict] = []
    t, x, y = 0.0, 100.0, 200.0
    for i, (gap, speed, curve) in enumerate(zip(_GAPS, _SPEEDS, _CURVE)):
        rnd = (rnd * 1103515245 + 12345) % 2**31
        wobble = 1.0 + ((rnd % 200) - 100) / 1000.0  # ±10%
        dist = gap * speed * wobble
        t += gap * wobble
        x += dist
        y += dist * curve
        events.append({"t": round(t, 2), "type": "mousemove", "x": round(x), "y": round(y)})
    for type_, gap in (("mousedown", 80.0), ("mouseup", 95.0), ("click", 3.0)):
        t += gap
        events.append({"t": round(t, 2), "type": type_, "x": round(x), "y": round(y)})
    return base64.b64encode(json.dumps(events).encode()).decode()


class Traced(Attacker):
    name = "traced"
    rung = 5

    def __init__(self) -> None:
        super().__init__()
        self.seed: str | None = None
        self.salt_mode: str | None = None
        self.env = consistent_env()
        self._counter = 0

    def prepare(self) -> None:
        status, body = self.get_json("/api/bootstrap")
        if status != 200:
            raise RuntimeError(f"bootstrap 失败: HTTP {status}")
        self.seed = body.get("seed")
        self.salt_mode = body.get("salt_mode")

    def _salt(self) -> str | None:
        if self.salt_mode == "static":
            return "bw-demo-salt"
        if self.salt_mode == "derived":
            return derive_salt(self.seed or "")
        if self.salt_mode == "runtime":
            return runtime_salt(self.seed or "", self.env)
        return None

    def headers(self, path: str, params: dict[str, str]) -> dict[str, str]:
        self._counter += 1
        headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-BW-JA3": "PLACEHOLDER_JA3_CHROME_142",
            "X-BW-Session": self.session,
            "X-BW-Env": self.env,
            "X-BW-Trace": synth_trace(self._counter),
        }
        salt = self._salt()
        if salt is None:
            return headers

        ts = str(int(time.time() * 1000))
        nonce = os.urandom(12).hex()
        payload = "\n".join(("GET", path, self.canonical_query(params), ts, nonce))
        headers["X-BW-Ts"] = ts
        headers["X-BW-Nonce"] = nonce
        headers["X-BW-Sign"] = sign(salt, payload)
        return headers


if __name__ == "__main__":
    main(Traced)
