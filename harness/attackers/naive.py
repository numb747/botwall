"""L0 · naive —— 什么都不做的采集器。

一个裸 GET，连 User-Agent 都不带。这是基线，也是绝大多数人写的第一版。

它的价值不在于能采到什么，而在于**它的失败归因**：在 open profile 上它跑满
成功率且成本最低，说明后面几级的额外成本全部来自防御，不是来自实现变复杂。
没有这条基线，其他数字就没有参照。
"""

from __future__ import annotations

from _base import Attacker, main


class Naive(Attacker):
    name = "naive"
    rung = 0

    def headers(self, path: str, params: dict[str, str]) -> dict[str, str]:
        return {}


if __name__ == "__main__":
    main(Naive)
