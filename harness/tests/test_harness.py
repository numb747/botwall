"""harness 的测试。

最重要的一条是 test_attackers_do_not_import_range_internals ——
攻击实现如果能 import 靶场的 signing.py，申报的 dev_hours 和测出的成本就都是
假的。这条约束不靠自觉，靠测试。
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from costladder_harness import load_attackers, load_rates
from costladder_harness.cost import Declared, Measured, compute
from costladder_harness.meter import MeterStats, RequestRecord, _extract_reasons
from costladder_harness.runner import ATTACKER_DIR

RATES = load_rates()


# --- 完整性：攻击实现不许抄答案 ---

#: 攻击实现绝不能碰的模块。能 import 就等于直接拿到签名算法，
#: 那么"逆向工时"就是编的，整张成本表都不成立。
FORBIDDEN_ROOTS = {"app", "costladder_harness", "range"}


def _all_source_files() -> list[Path]:
    """attackers/ 下的全部源码，含公共骨架 _base.py。

    完整性检查要覆盖骨架：它如果 import 了靶场内部，所有攻击实现都间接抄了答案。
    """
    return sorted(p for p in ATTACKER_DIR.glob("*.py") if p.name != "__init__.py")


def _attacker_files() -> list[Path]:
    """真正的攻击实现，不含下划线开头的内部模块。"""
    return [p for p in _all_source_files() if not p.name.startswith("_")]


def test_attacker_files_found():
    assert _attacker_files(), "没找到任何攻击实现"


@pytest.mark.parametrize("path", _all_source_files(), ids=lambda p: p.name)
def test_attackers_do_not_import_range_internals(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])

    leaked = imported & FORBIDDEN_ROOTS
    assert not leaked, (
        f"{path.name} import 了 {leaked}。攻击实现必须独立复现算法，"
        f"能 import 靶场内部模块就等于抄答案，申报工时与成本数据随之失效。"
    )


@pytest.mark.parametrize("path", _all_source_files(), ids=lambda p: p.name)
def test_attackers_have_no_external_targets(path: Path):
    """攻击实现不得内置任何指向外部主机的地址。见 docs/04-scope.md。"""
    source = path.read_text(encoding="utf-8")
    for line in source.splitlines():
        code = line.split("#")[0]
        assert "http://" not in code or "127.0.0.1" in code or "localhost" in code, (
            f"{path.name} 含非本地 URL: {line.strip()}"
        )
        assert "https://" not in code, f"{path.name} 含外部 URL: {line.strip()}"


def test_manifest_covers_every_attacker():
    specs = load_attackers()
    on_disk = {p.name for p in _attacker_files()}
    declared = {spec.entry.name for spec in specs.values()}
    assert on_disk == declared, f"清单与磁盘不一致：仅磁盘 {on_disk - declared}，仅清单 {declared - on_disk}"


#: 逆向家族：靠一次性工时爬阶梯的纯 HTTP 实现。它们内部才有"越高越贵"。
REVERSE_ENGINEERING_FAMILY = ("naive", "spoofed", "signed", "enveloped", "traced")


def test_reverse_engineering_family_dev_hours_climb_with_rung():
    """逆向家族内部：阶梯越高，申报工时应越大。

    注意这条**只对逆向家族成立**。browser 是故意的反例——它用高边际成本
    换掉逆向工时，以极低的 dev_hours 够到 L4，正是"能不能不用浏览器"这个
    取舍的另一端。把它算进来会（正确地）打破单调性。
    """
    specs = load_attackers()
    family = sorted(
        (specs[n] for n in REVERSE_ENGINEERING_FAMILY if n in specs),
        key=lambda s: s.rung,
    )
    hours = [s.dev_hours for s in family]
    assert hours == sorted(hours), f"逆向家族工时未随阶梯递增: {[(s.name, s.rung, s.dev_hours) for s in family]}"


def test_browser_trades_dev_hours_for_marginal_cost():
    """browser 应当以远低于同级逆向实现的工时够到 L4。"""
    specs = load_attackers()
    if "browser" not in specs or "enveloped" not in specs:
        pytest.skip("需要 browser 与 enveloped 才能比较")
    assert specs["browser"].rung == specs["enveloped"].rung == 4
    assert specs["browser"].dev_hours < specs["enveloped"].dev_hours


# --- 成本模型 ---


def make_measured(**overrides) -> Measured:
    base = dict(
        requests=10,
        total_bytes=100_000,
        cpu_seconds=1.0,
        wall_seconds=2.0,
        records_returned=100,
        records_verified=100,
    )
    base.update(overrides)
    return Measured(**base)


def test_zero_verified_is_infinite_not_cheap():
    """一条真数据都没采到的方案，单位成本是 ∞，不能折算成有限数字。

    否则它会在对比表里显得"很便宜"——这是成本模型里最危险的一种错误。
    """
    cost = compute(
        make_measured(records_returned=0, records_verified=0), Declared(0.0), RATES
    )
    assert cost.measured_per_10k == float("inf")
    assert cost.total_per_10k == float("inf")


def test_poisoned_records_inflate_retry_amplification():
    """blind 模式：HTTP 200 但内容是假的，R 必须反映出来。"""
    m = make_measured(records_returned=100, records_verified=25)
    assert m.poisoned_records == 75
    assert m.retry_amplification == pytest.approx(4.0)


def test_status_code_only_counting_would_understate_cost():
    """同一次运行，按状态码算 vs 按真值算，成本差 4 倍。"""
    honest = compute(make_measured(records_returned=100, records_verified=25), Declared(0.0), RATES)
    naive = compute(make_measured(records_returned=100, records_verified=100), Declared(0.0), RATES)
    assert honest.measured_per_10k == pytest.approx(naive.measured_per_10k * 4)


def test_measured_and_declared_never_merge_silently():
    cost = compute(make_measured(), Declared(dev_hours=10.0), RATES)
    assert cost.measured_per_10k > 0
    assert cost.dev_amortized_per_10k > 0
    assert cost.total_per_10k == pytest.approx(
        cost.measured_per_10k + cost.dev_amortized_per_10k
    )


def test_proxy_tier_scales_cost():
    m = make_measured()
    dc = compute(m, Declared(0.0), RATES, proxy_tier="datacenter")
    res = compute(m, Declared(0.0), RATES, proxy_tier="residential")
    ratio = RATES.proxy_usd_per_gb("residential") / RATES.proxy_usd_per_gb("datacenter")
    # 代理是这份 measured 里的主要成本项，倍数应当接近价格比
    assert res.measured_per_10k > dc.measured_per_10k
    assert res.proxy_usd == pytest.approx(dc.proxy_usd * ratio)


def test_unknown_proxy_tier_raises():
    with pytest.raises(KeyError):
        compute(make_measured(), Declared(0.0), RATES, proxy_tier="carrier-pigeon")


def test_dev_amortization_scales_with_revisions():
    """摊销期由目标站改版频率决定，不由项目周期决定。"""
    from costladder_harness.cost import amortized_dev_cost

    base = amortized_dev_cost(10.0, RATES)
    assert base == pytest.approx(
        10.0 * RATES.dev_usd_per_hour * RATES.revisions_per_year / (RATES.annual_records / 10_000)
    )
    assert amortized_dev_cost(0.0, RATES) == 0.0


def test_larger_volume_makes_reverse_engineering_cheaper():
    """L1 的核心经济学：采集量越大，一次性逆向工时摊得越薄。"""
    import dataclasses

    from costladder_harness.cost import amortized_dev_cost

    small = dataclasses.replace(RATES, annual_records=100_000)
    large = dataclasses.replace(RATES, annual_records=100_000_000)
    assert amortized_dev_cost(10.0, small) > amortized_dev_cost(10.0, large) * 100


# --- 计量 ---


def test_meter_stats_aggregate():
    stats = MeterStats()
    stats.add(RequestRecord("GET", "/api/items", 200, 500, 3000, 12.0))
    stats.add(RequestRecord("GET", "/api/items", 403, 500, 400, 8.0, ("sign_missing",)))
    stats.add(RequestRecord("GET", "/api/items", 403, 500, 400, 4.0, ("sign_missing", "ts_expired")))

    assert stats.requests == 3
    assert stats.total_bytes == 500 * 3 + 3000 + 400 + 400
    assert stats.status_counts == {200: 1, 403: 2}
    assert stats.block_reason_counts == {"sign_missing": 2, "ts_expired": 1}
    assert stats.summary()["median_duration_ms"] == 8.0


def test_extract_reasons_from_diagnostic_body():
    body = json.dumps(
        {"allowed": False, "blocked_by": [{"layer": "l2_transport", "reason": "ja3_absent"}]}
    ).encode()
    assert _extract_reasons(body) == ("ja3_absent",)


def test_extract_reasons_from_blind_response():
    """blind 模式返回的是正常数据，解不出原因码 —— 这正是它要制造的困难。"""
    body = json.dumps({"total": 5000, "items": [{"id": 0}]}).encode()
    assert _extract_reasons(body) == ()


def test_extract_reasons_tolerates_garbage():
    assert _extract_reasons(b"") == ()
    assert _extract_reasons(b"<html>nope</html>") == ()
    assert _extract_reasons(b"{not json") == ()
