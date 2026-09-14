"""输出 —— 决策表，不是 leaderboard。

每一行回答一个工程问题：给定这类防御特征，该停在哪一级、单位成本多少、
关键约束是什么。

两条格式化上的硬规矩：

  1. **实测量与申报量分列。** dev_hours 由攻击实现自报，harness 核实不了。
     把它和实测的字节数、CPU 加成一个数再显示，读者就无法判断哪部分可信。
  2. **采到 0 条真数据就显示 ∞，不显示某个有限数字。** 一条真数据都没采到的
     方案，单位成本就是无穷大；折算成有限数混进对比表里会让它看起来"很便宜"。
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from .rates import Rates
from .runner import RunResult

INF = float("inf")


def _fmt_usd(value: float) -> str:
    if value == INF:
        return "∞"
    if value == 0:
        return "0"
    if value < 0.001:
        # 纯 HTTP 方案的边际成本可以低到 1e-6 量级。截断成 0 会让"边际成本
        # 几乎为零、成本全在一次性工时上"这个关键结论看不出来。
        return f"{value:.2e}"
    if value < 0.01:
        return f"{value:.5f}"
    return f"{value:,.2f}"


def _fmt_ratio(value: float) -> str:
    return "∞" if value == INF else f"{value:.2f}×"


def decision_table(results: list[RunResult], rates: Rates) -> str:
    """按 profile 分组的决策表。"""
    lines: list[str] = []
    by_profile: dict[str, list[RunResult]] = {}
    for r in results:
        by_profile.setdefault(f"{r.profile} [{r.mode}/{r.form}]", []).append(r)

    for profile, group in by_profile.items():
        lines.append(f"\n══ {profile} ══")
        lines.append(
            f"{'攻击实现':<12}{'级':>3}  {'真值':>6}{'请求':>6}{'R':>7}"
            f"{'实测/万条':>12}{'摊销/万条':>12}{'合计/万条':>12}  主要拦截原因"
        )
        lines.append("─" * 96)
        for r in sorted(group, key=lambda x: x.rung):
            lines.append(
                f"{r.attacker:<12}L{r.rung:<2}  "
                f"{r.measured.records_verified:>6}"
                f"{r.measured.requests:>6}"
                f"{_fmt_ratio(r.measured.retry_amplification):>7}"
                f"{_fmt_usd(r.cost.measured_per_10k):>12}"
                f"{_fmt_usd(r.cost.dev_amortized_per_10k):>12}"
                f"{_fmt_usd(r.cost.total_per_10k):>12}"
                f"  {r.primary_block_reason or '—'}"
            )
            if r.measured.poisoned_records:
                lines.append(
                    f"{'':>14}⚠ 收到 {r.measured.poisoned_records} 条投毒数据"
                    f"（HTTP 200 但内容是假的）"
                )

        cheapest = _cheapest(group)
        if cheapest is not None:
            lines.append(
                f"\n  → 最优：{cheapest.attacker}（阶梯 L{cheapest.rung}），"
                f"合计 {_fmt_usd(cheapest.cost.total_per_10k)} / 万条"
            )
            _append_misjudgement_hint(lines, group, cheapest)
        else:
            lines.append("\n  → 本 profile 下没有任何实现采到真数据")

    lines.append(_footer(rates))
    return "\n".join(lines)


def _cheapest(group: list[RunResult]) -> RunResult | None:
    viable = [r for r in group if r.succeeded and r.cost.total_per_10k != INF]
    return min(viable, key=lambda r: r.cost.total_per_10k) if viable else None


def _append_misjudgement_hint(
    lines: list[str], group: list[RunResult], cheapest: RunResult
) -> None:
    """如果有更高级别的实现也能过，把它的代价倍数点出来。

    这正是本项目要防的那个误判：在低层被拦却以为要升级架构，
    白白付出高出一个数量级的成本。
    """
    higher = [
        r
        for r in group
        if r.succeeded and r.rung > cheapest.rung and r.cost.total_per_10k != INF
    ]
    if not higher or cheapest.cost.total_per_10k <= 0:
        return
    worst = max(higher, key=lambda r: r.cost.total_per_10k)
    factor = worst.cost.total_per_10k / cheapest.cost.total_per_10k
    if factor >= 1.2:
        lines.append(
            f"     误判成本：错选 {worst.attacker}（L{worst.rung}）要多付 {factor:.1f} 倍"
        )


def _footer(rates: Rates) -> str:
    return (
        f"\n{'─' * 96}\n"
        f"价格表 v{rates.version}（{rates.source.name}）· "
        f"代理 {rates.proxy_usd_per_gb('datacenter')}/GB · "
        f"算力 {rates.compute_usd_per_cpu_hour}/CPU·h · "
        f"开发 {rates.dev_usd_per_hour}/h\n"
        f"摊销：年采集 {rates.annual_records:,} 条 · 年改版 {rates.revisions_per_year} 次\n"
        f"人工打码地板线：${rates.human_floor_usd_per_solve:.5f}/次 "
        f"= ${rates.human_floor_usd_per_solve * 10000:,.2f}/万条\n"
        "\n"
        "「实测」由 harness 强制计量（字节数、CPU、请求数、真值校验），攻击实现无法影响。\n"
        "「摊销」来自攻击实现在 manifest 里的申报工时，harness 无法核实。两者分列，不混合。\n"
        "R = 吐出的记录数 / 已验证为真的记录数。blind 模式下投毒数据会让 R > 1。"
    )


def as_jsonl(results: Iterable[RunResult]) -> str:
    return "\n".join(json.dumps(r.to_dict(), ensure_ascii=False) for r in results)


def as_json(results: list[RunResult], rates: Rates) -> dict[str, Any]:
    return {
        "rates": rates.to_dict(),
        "results": [r.to_dict() for r in results],
    }
