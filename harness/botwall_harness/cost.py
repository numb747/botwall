"""成本模型 —— docs/03-cost-model.md 的可执行版本。

    C₁₀ₖ = 10000 × (实测边际成本 / 已验证记录数) + A_dev 摊销

最重要的一条设计约束：**实测量与申报量绝不混在一起上报。**

字节数、CPU 时间、请求数、成功率全部由 harness 实测（见 meter.py）。
而逆向工时 A_dev 无法自动测量，只能由攻击实现在 manifest 里申报。
把两者加成一个数再报出去，会让读者无法判断哪部分可信——所以 CostBreakdown
始终把它们分成两个字段，只在最终的 total 里合并，且 total 永远带标注。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .rates import Rates


@dataclass(frozen=True)
class Measured:
    """全部来自 harness 的实测，攻击实现无法影响。"""

    requests: int
    total_bytes: int
    cpu_seconds: float
    wall_seconds: float
    records_returned: int
    records_verified: int
    solves: int = 0

    @property
    def retry_amplification(self) -> float:
        """R = 1 / 成功率。

        分母用**已验证**的记录数，不是 HTTP 200 数。blind 模式下靶场返回的是
        200 + 投毒数据，只统计状态码会把投毒响应算成成功，从而高估通过率、
        低估 R，最终低估单位成本。
        """
        if self.records_verified <= 0:
            return float("inf")
        return self.records_returned / self.records_verified if self.records_returned else 1.0

    @property
    def poisoned_records(self) -> int:
        return max(0, self.records_returned - self.records_verified)


@dataclass(frozen=True)
class Declared:
    """由攻击实现在 manifest 里申报，harness 无法核实。

    单独成类不是为了好看，是为了让它在输出里永远显眼地和实测量分开。
    """

    dev_hours: float
    note: str = ""


@dataclass(frozen=True)
class CostBreakdown:
    # --- 实测部分 ---
    proxy_usd: float
    compute_usd: float
    solve_usd: float
    measured_per_10k: float
    # --- 申报部分 ---
    dev_amortized_per_10k: float
    # --- 合计 ---
    total_per_10k: float
    # --- 元数据 ---
    proxy_tier: str
    rates_version: int
    verified: int
    retry_amplification: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute(
    measured: Measured,
    declared: Declared,
    rates: Rates,
    *,
    proxy_tier: str = "datacenter",
) -> CostBreakdown:
    """把一次运行的实测数据折算成 C₁₀ₖ。

    已验证记录数为 0 时返回 inf —— 这是正确的：一条真数据都没采到的方案，
    单位成本就是无穷大，不该被折算成某个有限数字混进对比表里。
    """
    proxy_rate = rates.proxy_usd_per_gb(proxy_tier)
    proxy_usd = measured.total_bytes / 1e9 * proxy_rate
    compute_usd = measured.cpu_seconds / 3600.0 * rates.compute_usd_per_cpu_hour
    solve_usd = measured.solves / 1000.0 * rates.solve_usd_per_1k("human_farm")

    marginal = proxy_usd + compute_usd + solve_usd

    if measured.records_verified > 0:
        measured_per_10k = 10_000 * marginal / measured.records_verified
    else:
        measured_per_10k = float("inf")

    dev_per_10k = amortized_dev_cost(declared.dev_hours, rates)
    total = measured_per_10k + dev_per_10k

    return CostBreakdown(
        proxy_usd=round(proxy_usd, 8),
        compute_usd=round(compute_usd, 8),
        solve_usd=round(solve_usd, 8),
        # 边际成本在纯 HTTP 方案上非常小（本地靶场无真实代理开销时尤其如此），
        # 保 8 位才不会把阶梯各级之间的差别四舍五入掉。
        measured_per_10k=_round_inf(measured_per_10k, 8),
        dev_amortized_per_10k=round(dev_per_10k, 6),
        total_per_10k=_round_inf(total, 6),
        proxy_tier=proxy_tier,
        rates_version=rates.version,
        verified=measured.records_verified,
        retry_amplification=_round_inf(measured.retry_amplification, 3),
    )


def amortized_dev_cost(dev_hours: float, rates: Rates) -> float:
    """把申报的逆向工时摊到每万条。

    摊销期由目标站的**改版频率**决定，不是由项目周期决定：站点每季度改版一次，
    逆向就要每季度重做一次。所以年化成本是 单次工时 × 年改版次数。

    这是 L1 在成本模型里之所以特殊的原因——它付出的是一次性工时而非持续的
    边际成本，因此采集量越大、摊销期越长，逆向就越划算。
    """
    if dev_hours <= 0:
        return 0.0
    annual_dev_usd = dev_hours * rates.dev_usd_per_hour * rates.revisions_per_year
    batches_per_year = rates.annual_records / 10_000.0
    if batches_per_year <= 0:
        return float("inf")
    return annual_dev_usd / batches_per_year


def _round_inf(value: float, digits: int) -> float:
    return value if value == float("inf") else round(value, digits)
