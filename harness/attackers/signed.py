"""L1 · signed —— 复现请求签名，不用浏览器。

**这是整条阶梯上成本差最大的一跳，也是这门手艺真正的考场。**

逆向过程（这就是申报的 dev_hours 花在哪儿）
------------------------------------------
1. 抓包发现失败响应是 `sign_missing`，缺 X-BW-Ts / X-BW-Nonce / X-BW-Sign。
2. 同一接口连续调两次做 diff：变化的只有这三个头，其余全同。
   -> 说明签名的输入里含时间戳和随机数，不含任何服务端下发的会话密钥。
3. 把 lenient 档的响应打开（教学档会回显 signed_payload），确认序列化格式是
   `METHOD\\npath\\ncanonical_query\\nts\\nnonce`，且 query 按 key 排序。
   strict 档不回显，就只能从 sign.js 里读。
4. seed 从 /api/bootstrap 公开下发 —— 难点不在拿到 seed，在于复现
   seed -> salt 的变换。读 sign.js 的 deriveSalt：字符串反转 + 字符和取模 997。
5. 最后一段是 sha256(salt + payload) 取前 32 位十六进制。

本文件**不 import 靶场的 signing.py**。整个 harness 有一条测试强制这一点：
能 import 就等于抄答案，测出来的 dev_hours 和成本都是假的。

成本模型里的特殊性
------------------
这一级付出的是**一次性逆向工时**，而非持续的边际成本。逆出来之后单次请求的
边际成本和 L0 几乎相同（只多了三个头的字节数）。所以：

    值不值得逆向 = (被顶到 L3/L4 的边际成本增量 × 预期总采集量) > 逆向工时成本

采集量越大、摊销期越长，逆向越划算。这是唯一一项"规模越大回报越高"的能力。
"""

from __future__ import annotations

import hashlib
import os
import time

from _base import Attacker, main
from spoofed import UA


def derive_salt(seed: str) -> str:
    """从 sign.js 的 deriveSalt 复现。字符串反转 + 字符和取模。"""
    checksum = sum(ord(c) for c in seed) % 997
    return hashlib.sha256(f"{seed[::-1]}{checksum}".encode()).hexdigest()[:16]


def sign(salt: str, payload: str) -> str:
    return hashlib.sha256((salt + payload).encode()).hexdigest()[:32]


class Signed(Attacker):
    name = "signed"
    rung = 1

    def __init__(self) -> None:
        super().__init__()
        self.seed: str | None = None
        self.salt_mode: str | None = None
        self._salt: str | None = None

    def prepare(self) -> None:
        # bootstrap 这一次请求也走计量代理，所以它的流量会计入成本。
        # 真实世界里这对应"每次起管线要先拉一次页面拿 seed"的固定开销。
        status, body = self.get_json("/api/bootstrap")
        if status != 200:
            raise RuntimeError(f"bootstrap 失败: HTTP {status}")
        self.seed = body.get("seed")
        self.salt_mode = body.get("salt_mode")
        self._salt = self._compute_salt()

    def _compute_salt(self) -> str | None:
        if self.salt_mode == "static":
            # static 档的 salt 明文写在 sign.js 里，读一遍即可
            return "bw-demo-salt"
        if self.salt_mode == "derived":
            return derive_salt(self.seed or "")
        # runtime 档这里处理不了：salt 与环境快照绑定，见 enveloped.py
        return None

    def headers(self, path: str, params: dict[str, str]) -> dict[str, str]:
        headers = {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-BW-JA3": "PLACEHOLDER_JA3_CHROME_142",
            "X-BW-Session": self.session,
        }
        if self._salt is None:
            return headers

        ts = str(int(time.time() * 1000))
        # nonce 必须每次都变：服务端有重放表，抓一个包反复重放会被
        # nonce_replayed 拦掉。这条约束正是"必须真正复现算法"的原因。
        nonce = os.urandom(12).hex()
        payload = "\n".join(("GET", path, self.canonical_query(params), ts, nonce))
        headers["X-BW-Ts"] = ts
        headers["X-BW-Nonce"] = nonce
        headers["X-BW-Sign"] = sign(self._salt, payload)
        return headers


if __name__ == "__main__":
    main(Signed)
