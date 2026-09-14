"""靶场核心数据结构。

三个概念：
  Probe   —— 从一次请求里提取出的、所有层共用的证据快照
  Verdict —— 单层的判定结果，带归因信息
  RangeState —— 跨请求的可变状态（频率计数、nonce 重放表、会话）

层与层之间不直接通信，只通过 RangeState 共享状态，且各自只读写自己那部分。
这样任何一层都能被单独拔掉而不破坏其他层。
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Strength(str, Enum):
    """层的强度档。off 档的层根本不会被实例化。"""

    OFF = "off"
    LENIENT = "lenient"
    STRICT = "strict"
    PARANOID = "paranoid"

    @classmethod
    def _missing_(cls, value: object) -> "Strength | None":
        # YAML 1.1 把不加引号的 off 解析成布尔 False（on/yes/no 同理）。
        # 要求 profile 作者写 "off" 只会制造一个反复踩的坑，在这里统一收口。
        if value is False:
            return cls.OFF
        if isinstance(value, str):
            return cls.__members__.get(value.strip().upper())
        return None

    def at_least(self, other: "Strength") -> bool:
        order = [Strength.OFF, Strength.LENIENT, Strength.STRICT, Strength.PARANOID]
        return order.index(self) >= order.index(other)


@dataclass(frozen=True)
class Probe:
    """一次请求的证据快照。

    所有层只能看到这个对象，看不到框架的 Request。这条约束是有意的：
    它保证层不会意外依赖某个 web 框架的细节，也让单测可以直接构造 Probe。
    """

    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]  # key 一律小写
    cookies: dict[str, str]
    body: bytes
    client_ip: str
    received_at: float  # 服务端接收时刻，单位秒

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def canonical_query(self) -> str:
        """查询参数按 key 字典序排序后以 & 连接。签名计算用。"""
        return "&".join(f"{k}={self.query[k]}" for k in sorted(self.query))


@dataclass
class Verdict:
    """单层判定结果。

    passed=False 时 reason 必须有值——归因是靶场存在的理由，
    没有 reason 的失败判定等同于真实站点，也就没有价值。

    score 是该层对累计风险分的贡献，只在 form=score 的 profile 下使用。
    """

    layer: str
    passed: bool
    score: float = 0.0
    reason: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    # 该层对应成本阶梯的级号：被它拦住，至少要爬到这一级
    ladder_rung: int = 0

    def __post_init__(self) -> None:
        if not self.passed and not self.reason:
            raise ValueError(f"{self.layer}: 失败判定必须携带 reason")

    @classmethod
    def ok(cls, layer: str, **detail: Any) -> "Verdict":
        return cls(layer=layer, passed=True, detail=detail)


class RangeState:
    """跨请求的可变状态。

    进程内存储，单进程单事件循环下无需加锁。多 worker 部署会让频率统计和
    nonce 重放表失效——这是已知限制，靶场默认以单 worker 运行。
    """

    def __init__(self, nonce_ttl_seconds: float = 300.0) -> None:
        # L1: ip -> 请求时刻的滑动窗口
        self.request_times: dict[str, deque[float]] = defaultdict(deque)
        # L1: ip -> 活跃会话 id 集合
        self.ip_sessions: dict[str, set[str]] = defaultdict(set)
        # L3: nonce -> 首次出现时刻
        self.seen_nonces: dict[str, float] = {}
        self.nonce_ttl = nonce_ttl_seconds
        # L6: 会话 id -> 待验证的挑战
        self.pending_challenges: dict[str, dict[str, Any]] = {}
        # 会话 id -> 累计风险分（form=score 时使用）
        self.session_risk: dict[str, float] = defaultdict(float)

    # --- L1 ---

    def record_request(self, ip: str, now: float, window: float) -> int:
        """记录一次请求并返回窗口内的请求数。"""
        times = self.request_times[ip]
        times.append(now)
        cutoff = now - window
        while times and times[0] < cutoff:
            times.popleft()
        return len(times)

    # --- L3 ---

    def check_and_record_nonce(self, nonce: str, now: float) -> bool:
        """返回 True 表示这是首次出现。顺带清理过期项。"""
        if self.seen_nonces:
            cutoff = now - self.nonce_ttl
            expired = [n for n, t in self.seen_nonces.items() if t < cutoff]
            for n in expired:
                del self.seen_nonces[n]
        if nonce in self.seen_nonces:
            return False
        self.seen_nonces[nonce] = now
        return True

    def reset(self) -> None:
        """清空全部状态。用于测试之间的隔离。"""
        self.request_times.clear()
        self.ip_sessions.clear()
        self.seen_nonces.clear()
        self.pending_challenges.clear()
        self.session_risk.clear()


def now() -> float:
    return time.time()
