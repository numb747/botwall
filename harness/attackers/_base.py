"""攻击实现的公共骨架 —— 只负责协议，不负责绕过。

协议
----
    输入   环境变量 BW_TARGET / BW_ITEMS_WANTED / BW_PAGE_SIZE
    输出   stdout 逐行 JSONL，每行一条采到的记录
    诊断   stderr（harness 单独捕获，不参与计量）
    退出   0 = 采够了，非 0 = 放弃

BW_TARGET 指向 harness 的计量代理，不是靶场。攻击实现不知道靶场的真实地址，
因此无法绕过计量。

为什么各个攻击实现共用这个骨架
------------------------------
共用的部分只有"循环、取页、吐 JSONL"。它们之间**唯一的差别就是 headers()**，
也就是在成本阶梯上爬了几级。差异被压缩到这一个方法上，对比才干净：
测出来的成本差只能来自阶梯级别，不可能来自主循环写法的不同。

这些实现只面向本地靶场，不含任何指向外部主机的目标配置。见 docs/04-scope.md。
"""

from __future__ import annotations

import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

#: 连续失败多少次就放弃。设这个上限是为了让"根本过不去"的组合能终止，
#: 否则重试放大系数 R 会发散成一个没有意义的大数。
MAX_CONSECUTIVE_FAILURES = 15


class Attacker:
    """子类只需要覆写 rung / name / headers()，必要时覆写 prepare()。"""

    name: str = "base"
    #: 本实现对应成本阶梯的第几级
    rung: int = 0

    def __init__(self) -> None:
        self.target = os.environ.get("BW_TARGET", "http://127.0.0.1:8900").rstrip("/")
        self.wanted = int(os.environ.get("BW_ITEMS_WANTED", "200"))
        self.page_size = int(os.environ.get("BW_PAGE_SIZE", "20"))
        self.session = os.urandom(8).hex()

    # --- 子类接口 ---

    def prepare(self) -> None:
        """可选的预备动作，例如拉 bootstrap 拿 seed。"""

    def headers(self, path: str, params: dict[str, str]) -> dict[str, str]:
        raise NotImplementedError

    # --- 公共设施 ---

    @staticmethod
    def canonical_query(params: dict[str, str]) -> str:
        """查询参数按 key 字典序排序后以 & 连接。

        注意这是从抓包和 sign.js 里推出来的规则，不是从服务端代码抄的。
        参数顺序不影响签名，但序列化格式必须逐字节一致。
        """
        return "&".join(f"{k}={params[k]}" for k in sorted(params))

    def get_json(self, path: str, params: dict[str, str] | None = None) -> tuple[int, dict]:
        params = params or {}
        url = f"{self.target}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(url, headers=self.headers(path, params))
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except ValueError:
                return exc.code, {}
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"[{self.name}] 传输失败: {exc}", file=sys.stderr)
            return 0, {}

    def log(self, message: str) -> None:
        print(f"[{self.name}] {message}", file=sys.stderr)

    # --- 主循环 ---

    def run(self) -> int:
        try:
            self.prepare()
        except Exception as exc:  # noqa: BLE001 —— 预备失败也是一种失败，要计入而不是崩掉
            self.log(f"prepare 失败: {exc}")
            return 2

        collected = 0
        offset = 0
        consecutive_failures = 0
        max_pages = math.ceil(self.wanted / self.page_size) * 3 + 10

        for _ in range(max_pages):
            if collected >= self.wanted:
                break

            params = {"limit": str(self.page_size), "offset": str(offset)}
            status, body = self.get_json("/api/items", params)

            if status != 200:
                consecutive_failures += 1
                reasons = [b.get("reason") for b in body.get("blocked_by", [])]
                self.log(f"HTTP {status} offset={offset} 原因={reasons or '未知'}")
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    self.log("连续失败过多，放弃")
                    return 1
                continue

            consecutive_failures = 0
            items = body.get("items", [])
            if not items:
                self.log(f"offset={offset} 返回空页，结束")
                break

            for record in items:
                # 只负责吐出来。真伪由 harness 事后校验——攻击实现自己是
                # 判断不了的，blind 模式下它拿到的 200 和真的一模一样。
                sys.stdout.write(json.dumps(record, ensure_ascii=False) + "\n")
            sys.stdout.flush()

            collected += len(items)
            offset += len(items)

        self.log(f"结束，共吐出 {collected} 条")
        return 0 if collected > 0 else 1


def main(cls: type[Attacker]) -> None:
    sys.exit(cls().run())
