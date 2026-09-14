"""L3/L4 · enveloped —— 伪造自洽的运行时环境，处理 runtime 档的签名。

在 signed 的基础上多做两件事：
  1. 提交一份**互相自洽**的环境快照，过 L4 运行时层
  2. 用该快照参与 salt 计算，过 L3 的 runtime 档

一个必须讲清楚的发现
--------------------
靶场的 runtime 档把 salt 与环境快照绑定，看起来"绕不开真实 JS 运行时"。
但实际上它绕得开：客户端可以提交一份**自己编的、但内部自洽的**快照，再用
同一份快照算 salt。服务端无从分辨快照是采来的还是编的，它只能校验自洽性。

这不是靶场的设计缺陷，而是对现实的正确建模。真实世界的环境检测同样只能验
自洽性——伪造单个属性很容易，让几十个属性互相不矛盾才是成本所在。所以这一
级的成本不体现在**边际请求成本**上（多几个头而已），而体现在 **dev_hours**
上：服务端每多一项交叉校验，伪造方就要多花工时去对齐一项。

推论：针对这类防御，防御方该做的不是"加难度"，而是"加检查项的数量和多样性"。
这两者在成本模型里的作用完全不同——前者抬边际成本（对攻击方影响小），
后者抬一次性工时（对攻击方影响大，且随规模摊薄，所以对大规模采集方影响小）。

局限
----
靶场当前的 canvasHash 判据只检查"非退化、长度足够"，因此可以直接编。要真正
逼出浏览器，服务端需要持有设备类别到渲染结果的对照表并做实质校验。这一点
在 README 的已知限制里记着。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time

from _base import Attacker, main
from signed import derive_salt, sign
from spoofed import UA


def runtime_salt(seed: str, env_snapshot: str) -> str:
    """从 sign.js 的 runtimeSalt 复现：derived 的结果再与环境快照混合。"""
    return hashlib.sha256((derive_salt(seed) + env_snapshot).encode()).hexdigest()[:16]


def consistent_env() -> str:
    """一份互相自洽的环境快照。

    每个字段都要和 UA 声明的平台对上：
      UA 说 Windows      -> platform 必须是 Win32/Win64
      平台是 Windows      -> webglVendor 不能是 Apple
      不是软件渲染        -> renderer 不能含 SwiftShader / llvmpipe
      canvasHash 非退化   -> 不能是 0 / 空 / 过短
      collectMs 在人类设备的合理区间

    把这几条对齐就是这一级 dev_hours 的全部内容。服务端每加一项校验，
    这里就要多一行，也就多一点工时。
    """
    env = {
        "userAgent": UA,
        "platform": "Win32",
        "languages": ["zh-CN", "zh"],
        "hardwareConcurrency": 8,
        "webdriver": False,
        "webglVendor": "Google Inc.",
        "webglRenderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
        "canvasHash": "3f9a1c74be205d81",
        "windowKeys": [],
        "collectMs": 14.3,
    }
    return base64.b64encode(json.dumps(env).encode()).decode()


class Enveloped(Attacker):
    name = "enveloped"
    rung = 4

    def __init__(self) -> None:
        super().__init__()
        self.seed: str | None = None
        self.salt_mode: str | None = None
        # 快照只算一次并全程复用：它必须与签名时用的那一份逐字节相同，
        # 否则服务端重算 salt 会对不上（sign_mismatch）。
        self.env = consistent_env()

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
        headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-BW-JA3": "PLACEHOLDER_JA3_CHROME_142",
            "X-BW-Session": self.session,
            "X-BW-Env": self.env,
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
    main(Enveloped)
