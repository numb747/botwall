"""价格表加载。

价格表决定输出的绝对数值，所以它必须是显式的、带版本号的、可整体替换的数据，
而不是散落在代码里的魔法数字。任何对外引用的结果都要附上 rates 版本。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

HARNESS_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RATES = HARNESS_ROOT / "rates.yaml"


@dataclass(frozen=True)
class Rates:
    version: int
    currency: str
    _proxy: dict[str, float]
    compute_usd_per_cpu_hour: float
    _solve: dict[str, float]
    dev_usd_per_hour: float
    annual_records: int
    revisions_per_year: int
    source: Path

    def proxy_usd_per_gb(self, tier: str) -> float:
        if tier not in self._proxy:
            raise KeyError(f"未知的代理档位 {tier!r}；可用: {sorted(self._proxy)}")
        return self._proxy[tier]

    def solve_usd_per_1k(self, kind: str) -> float:
        if kind not in self._solve:
            raise KeyError(f"未知的求解方式 {kind!r}；可用: {sorted(self._solve)}")
        return self._solve[kind]

    @property
    def proxy_tiers(self) -> list[str]:
        return sorted(self._proxy)

    @property
    def human_floor_usd_per_solve(self) -> float:
        """人工打码的单次价格 —— 成本模型里的地板线。

        任何自动化方案，如果单次成本高于它，在经济上就没有存在理由：
        攻击者会直接买人工。这条线把"这个方案值不值得做"变成一个可计算、
        可反驳的判断，而不是观点。
        """
        return self.solve_usd_per_1k("human_farm") / 1000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "currency": self.currency,
            "proxy_usd_per_gb": dict(self._proxy),
            "compute_usd_per_cpu_hour": self.compute_usd_per_cpu_hour,
            "solve_usd_per_1k": dict(self._solve),
            "dev_usd_per_hour": self.dev_usd_per_hour,
            "annual_records": self.annual_records,
            "revisions_per_year": self.revisions_per_year,
        }


def load_rates(path: str | Path | None = None) -> Rates:
    target = Path(path) if path else DEFAULT_RATES
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    amortization = raw.get("amortization", {}) or {}
    return Rates(
        version=int(raw.get("version", 0)),
        currency=raw.get("currency", "USD"),
        _proxy={k: float(v) for k, v in (raw.get("proxy_usd_per_gb") or {}).items()},
        compute_usd_per_cpu_hour=float(raw.get("compute_usd_per_cpu_hour", 0.0)),
        _solve={k: float(v) for k, v in (raw.get("solve_usd_per_1k") or {}).items()},
        dev_usd_per_hour=float(raw.get("dev_usd_per_hour", 0.0)),
        annual_records=int(amortization.get("annual_records", 10_000_000)),
        revisions_per_year=int(amortization.get("revisions_per_year", 1)),
        source=target,
    )
