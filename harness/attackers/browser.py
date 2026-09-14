"""L4 · browser —— 不逆向，直接在真浏览器里跑站点自己的 JS。

与整条 HTTP 阶梯相反的经济路径
------------------------------
signed / enveloped / traced 付出的是**一次性逆向工时**：读懂 sign.js、复现
salt 变换、对齐环境字段。逆出来之后单次请求几乎不花钱。

这个实现反过来：**dev_hours 极低**（不读签名算法，让浏览器执行站点自己的
signedFetch），代价是**高昂的边际成本**——每次采集都要跑一个真浏览器，
CPU 和"加载整套页面资源"的流量都是持续开销。

这正是成本阶梯上半段的取舍，也是"能不能不用浏览器"这个核心论点的两端。
本实现是唯一真正付出浏览器边际成本的攻击实现，因此也是唯一能让 L4/L5 的
~50× 惩罚在实测数字里显形的那个。

它做不到什么，同样是结果
------------------------
headless chromium 的 WebGL 是软件渲染（SwiftShader），过不了 L4 的 paranoid
档 webgl_mismatch。这不是实现偷懒——它如实说明：运行时层的严格档要逼出的
正是**真实 GPU / 真实设备**，那一步的成本才真正跳到另一个量级。所以本实现
能过 cdn-standard 和 api-signed，过不了 hardened，这个边界本身就是一条结论。
"""

from __future__ import annotations

import json
import sys

from _base import Attacker, main

# 与 spoofed 一致的自报 JA3（tlsfront 未实现前的开发模式替身）。
# 用 Playwright 的 set_extra_http_headers 附到**每个**请求上，含页面导航本身。
JA3 = "PLACEHOLDER_JA3_CHROME_142"
# UA 必须与平台自洽：headless chromium 跑在 Linux 上，就用 Linux Chrome 的 UA，
# 否则 L4 会因为 "UA 说 Windows、platform 却是 Linux" 判 navigator_inconsistent。
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)

# 抹掉自动化痕迹。这几行就是这一级 dev_hours 的主要内容——不是逆向签名，
# 而是让浏览器看起来不像被程序驱动的。
STEALTH = "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"


class Browser(Attacker):
    name = "browser"
    rung = 4

    def run(self) -> int:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.log("未安装 playwright，跳过。装法见 harness/README.md")
            return 2

        collected = 0
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(user_agent=UA)
                context.set_extra_http_headers({"X-BW-JA3": JA3, "X-BW-Session": self.session})
                context.add_init_script(STEALTH)
                page = context.new_page()

                # 导航到靶场的落地页。BW_TARGET 指向计量代理，所以页面本身、
                # sign.js、bootstrap、items 的流量全部经过代理，一并计入成本。
                page.goto(f"{self.target}/static/index.html", wait_until="networkidle")
                page.wait_for_function("window.bwFetch !== undefined", timeout=10000)

                offset = 0
                consecutive_failures = 0
                while collected < self.wanted:
                    self._wander(page)  # 产生真实指针轨迹，供 L5 判定
                    result = page.evaluate(
                        "async ([p, o, l]) => await window.bwFetch(p, "
                        "{limit: String(l), offset: String(o)})",
                        ["/api/items", offset, self.page_size],
                    )
                    status = result.get("status")
                    body = result.get("body") or {}
                    if status != 200:
                        consecutive_failures += 1
                        reasons = [b.get("reason") for b in body.get("blocked_by", [])]
                        self.log(f"HTTP {status} offset={offset} 原因={reasons or '未知'}")
                        if consecutive_failures >= 8:
                            self.log("连续失败过多，放弃")
                            browser.close()
                            return 1
                        continue

                    consecutive_failures = 0
                    items = body.get("items", [])
                    if not items:
                        break
                    for record in items:
                        sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
                    sys.stdout.flush()
                    collected += len(items)
                    offset += len(items)

                browser.close()
        except Exception as exc:  # noqa: BLE001
            self.log(f"浏览器运行失败: {exc}")
            return 2 if collected == 0 else 1

        self.log(f"结束，共吐出 {collected} 条")
        return 0 if collected > 0 else 1

    @staticmethod
    def _wander(page) -> None:
        """在页面上做几段真实的鼠标移动。

        用 Playwright 的 steps 分段插值，产生带中间点的轨迹。真浏览器的鼠标
        事件是否能过 L5 的 paranoid 档，是本实现要顺带回答的问题之一——
        answer 见 harness/README.md 的实测结果。
        """
        moves = [(120, 90, 12), (300, 180, 18), (240, 260, 10), (420, 200, 15)]
        for x, y, steps in moves:
            page.mouse.move(x, y, steps=steps)
        page.mouse.down()
        page.mouse.up()

    def headers(self, path: str, params: dict[str, str]) -> dict[str, str]:
        # 浏览器不走 _base 的 urllib 主循环，这个方法用不到。
        raise NotImplementedError


if __name__ == "__main__":
    main(Browser)
