"""L0 · spoofed —— 换一个具备指纹伪装能力的 HTTP 客户端。

相对 naive 只多做一件事：带上浏览器 UA 和一个真浏览器的 TLS 指纹。

**这是整条阶梯上最重要的一级，因为它的成本增量几乎为零。**
在 L2 传输层被拦时，正确应对就是换个客户端库（真实世界里是从 requests 换到
curl_cffi 一类），而不是上浏览器。误判成"要上浏览器"会直接跳到阶梯 L4，
白白付出约 50 倍成本。

关于 X-CL-JA3
-------------
真实世界里 TLS 指纹由客户端库的握手行为决定，伪装靠换库实现。靶场的
tlsfront 前置代理尚未实现，所以这里用自报的头代替。这是**开发模式的
简化**，不是真实的伪装成本——tlsfront 就位后这一行要换成真的换库。
换库本身的成本增量依然接近零，所以结论方向不变，但绝对数字会变。
"""

from __future__ import annotations

from _base import Attacker, main

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)


class Spoofed(Attacker):
    name = "spoofed"
    rung = 0

    def headers(self, path: str, params: dict[str, str]) -> dict[str, str]:
        return {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            # 必须与 UA 声明的浏览器族一致，否则 paranoid 档的交叉校验会抓到。
            # 换 UA 绕不过这一条 —— 这正是交叉一致性比单点校验强的地方。
            "X-CL-JA3": "PLACEHOLDER_JA3_CHROME_142",
            "X-CL-Session": self.session,
        }


if __name__ == "__main__":
    main(Spoofed)
