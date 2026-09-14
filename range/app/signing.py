"""签名方案 —— L3 协议层的算法实现。

这套方案是自造的，只在**结构上**与生产环境中常见的请求签名同构：
时效戳 + 随机数 + 盐 + 排序后的参数序列化。不含任何厂商的实际逻辑。

三档难度的区别只在 salt 从哪来：

  static   salt 明文写在 sign.js 里            -> 读一遍 JS 即可，停在阶梯 L1
  derived  salt 由页面下发的 seed 经变换得到   -> 要读懂混淆代码，仍停在 L1
  runtime  salt 的一部分取自浏览器运行时环境   -> JS 里拿不到完整值，被顶到 L3+

runtime 档是 L3 与 L4 的耦合点：签名需要环境快照，于是绕不开真实 JS 运行时。
这个耦合是刻意设计的，它复现了真实站点上"签名依赖运行时"这一最难降级的形态。
"""

from __future__ import annotations

import hashlib


def canonical_payload(method: str, path: str, canonical_query: str, ts: str, nonce: str) -> str:
    return "\n".join((method.upper(), path, canonical_query, ts, nonce))


def sign(salt: str, payload: str) -> str:
    return hashlib.sha256((salt + payload).encode("utf-8")).hexdigest()[:32]


def derive_salt(seed: str) -> str:
    """`derived` 档的 salt 变换。

    刻意做成"可静态逆向但要读懂代码"：字符串反转 + 字符和取模。
    sign.js 里有一份等价的混淆实现，两边必须一致，改这里就要同步改那里。
    """
    checksum = sum(ord(c) for c in seed) % 997
    return hashlib.sha256(f"{seed[::-1]}{checksum}".encode("utf-8")).hexdigest()[:16]


def runtime_salt(seed: str, env_snapshot: str) -> str:
    """`runtime` 档的 salt：derived 的结果再与环境快照绑定。

    env_snapshot 是 X-CL-Env 头的原始值（base64 串本身，不解码）。
    服务端按同样方式重算，因此客户端必须提交与签名时一致的环境快照。
    """
    base = derive_salt(seed)
    mixed = hashlib.sha256((base + env_snapshot).encode("utf-8")).hexdigest()[:16]
    return mixed


def compute(
    salt_mode: str,
    seed: str,
    static_salt: str,
    env_snapshot: str,
    method: str,
    path: str,
    canonical_query: str,
    ts: str,
    nonce: str,
) -> str:
    """按档位算出期望签名。服务端与参考客户端共用这个入口。"""
    if salt_mode == "static":
        salt = static_salt
    elif salt_mode == "derived":
        salt = derive_salt(seed)
    elif salt_mode == "runtime":
        salt = runtime_salt(seed, env_snapshot)
    else:
        raise ValueError(f"未知的 salt_mode: {salt_mode}")
    return sign(salt, canonical_payload(method, path, canonical_query, ts, nonce))
