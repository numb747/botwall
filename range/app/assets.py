"""页面资产生成器 —— 让"浏览器要加载整页"这件事产生真实的流量成本。

真实站点的页面动辄几 MB：框架 bundle、应用 JS、CSS、图片、字体。纯 HTTP
客户端只取那个精简的 JSON 接口，浏览器却要把这一整套都拉下来。这个不对称
是"能不能不用浏览器"这条成本阶梯的物理基础，之前的靶场页面太小（几十 KB），
把它抹平了，导致 browser 的边际成本被严重低估。

这里按一张尺寸表**确定性地**生成资产字节流（不落盘、不进仓库、跨机一致）。

关于尺寸口径
------------
表里的数字是**过线字节数**（proxy 实际计费的、压缩后的传输量），不是 JS 源码
的原始大小。所以生成的是不可压缩的伪随机字节并原样传输——计量到的就等于
过线量，避免了"服务端要不要 gzip、代理按压缩前还是压缩后计费"这一堆纠缠。

尺寸可用环境变量 BW_PAGE_WEIGHT 整体缩放（默认 1.0），便于做敏感性分析。
"""

from __future__ import annotations

import hashlib
import os

#: 一个中等内容平台首屏的典型过线构成（KB）。保守取值——真实站点常更重。
#: 数字是过线（压缩后）量级，不是源码大小。
_ASSET_KB: dict[str, tuple[int, str]] = {
    "vendor.js": (320, "application/javascript"),   # 框架 bundle
    "app.js": (90, "application/javascript"),        # 应用逻辑
    "app.css": (45, "text/css"),
    "hero.jpg": (180, "image/jpeg"),                 # 首屏大图
    "sprite.png": (60, "image/png"),
    "font-latin.woff2": (42, "font/woff2"),
    "font-cjk.woff2": (58, "font/woff2"),
}


def _weight() -> float:
    try:
        return max(0.0, float(os.environ.get("BW_PAGE_WEIGHT", "1.0")))
    except ValueError:
        return 1.0


def asset_names() -> list[str]:
    return list(_ASSET_KB)


def content_type(name: str) -> str:
    return _ASSET_KB[name][1]


def asset_bytes(name: str) -> bytes:
    """生成 name 对应的确定性、不可压缩的字节流。

    不可压缩靠 sha256 计数器流实现：同一个 name 在任何机器上都得到同样的字节，
    但这些字节没有冗余，gzip 压不动，因此"计量到的字节数 = 过线字节数"。
    """
    kb, _ = _ASSET_KB[name]
    size = int(kb * 1024 * _weight())
    if size <= 0:
        return b""
    out = bytearray()
    counter = 0
    seed = name.encode()
    while len(out) < size:
        out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:size])


def total_page_kb() -> float:
    """当前权重下整页资产的过线总量（KB），供文档与自检引用。"""
    return sum(kb for kb, _ in _ASSET_KB.values()) * _weight()
