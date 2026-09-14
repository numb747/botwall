"""被采集的数据源 —— 全部为程序生成的合成数据，不含任何真实个人信息。

数据是确定性的：给定 id 必然生成同一条记录，不依赖随机源。这是可复现性的
要求，也让 harness 能在事后校验采到的数据是真是假。

blind 模式下返回的"假数据"在结构上完全合法，只是内容错误。这复现了成熟
防御方的做法：不告诉攻击者失败了，让他悄无声息地采走一堆垃圾。对应地，
harness 必须用 verify_record 事后校验，否则测出来的成功率是虚高的。
"""

from __future__ import annotations

import hashlib
from typing import Any

_CATEGORIES = ("电子", "家居", "服饰", "食品", "图书", "运动")
_ADJECTIVES = ("便携", "静音", "折叠", "轻量", "加厚", "速干", "复古", "多功能")
_NOUNS = ("水壶", "台灯", "背包", "坐垫", "耳机", "毛毯", "手册", "支架")

TOTAL_RECORDS = 5000


def _h(seed: str) -> int:
    return int.from_bytes(hashlib.sha256(seed.encode()).digest()[:8], "big")


def make_record(item_id: int, *, poisoned: bool = False) -> dict[str, Any]:
    """生成第 item_id 条记录。

    poisoned=True 时返回结构合法但内容错误的版本——字段齐全、类型正确、
    取值在合理区间内，只是和真值对不上。肉眼和 schema 校验都看不出来。
    """
    salt = "poison" if poisoned else "true"
    h = _h(f"{salt}:{item_id}")
    return {
        "id": item_id,
        "title": f"{_ADJECTIVES[h % len(_ADJECTIVES)]}{_NOUNS[(h >> 8) % len(_NOUNS)]}",
        "category": _CATEGORIES[(h >> 16) % len(_CATEGORIES)],
        "price_cents": 990 + (h >> 24) % 49010,
        "rating": round(3.0 + ((h >> 40) % 200) / 100.0, 2),
        "review_count": (h >> 48) % 4000,
        "checksum": hashlib.sha256(f"{salt}:{item_id}".encode()).hexdigest()[:12],
    }


def verify_record(record: dict[str, Any]) -> bool:
    """事后校验一条记录是真值还是 blind 模式下的投毒数据。

    harness 必须调用它。只统计 HTTP 200 的成功率会把投毒响应算成成功，
    从而高估通过率、低估重试放大系数 R，最终低估单位成本。
    """
    try:
        item_id = int(record["id"])
    except (KeyError, TypeError, ValueError):
        return False
    return record.get("checksum") == make_record(item_id)["checksum"]


def page(offset: int, limit: int, *, poisoned: bool = False) -> dict[str, Any]:
    limit = max(1, min(limit, 100))
    offset = max(0, min(offset, TOTAL_RECORDS))
    ids = range(offset, min(offset + limit, TOTAL_RECORDS))
    return {
        "total": TOTAL_RECORDS,
        "offset": offset,
        "limit": limit,
        "items": [make_record(i, poisoned=poisoned) for i in ids],
    }
