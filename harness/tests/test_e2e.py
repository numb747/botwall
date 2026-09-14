"""端到端：真的把靶场拉起来跑一遍。

比单测慢（每例要起一次 uvicorn），但它是唯一能验证"计量代理 + 子进程 +
真值校验"这条链路真的接通的测试。用 -m "not e2e" 可以跳过。
"""

from __future__ import annotations

import pytest

from botwall_harness import load_attackers, load_rates, run_once

pytestmark = pytest.mark.e2e

RATES = load_rates()
ATTACKERS = load_attackers()


def test_naive_succeeds_on_open_profile():
    """基线：无防御时 naive 应当采满且零拦截。

    这条不通过，说明后面所有的成本差都可能来自实现缺陷而非防御。
    """
    result = run_once("open", ATTACKERS["naive"], RATES, items=40, page_size=20)
    assert result.exit_code == 0
    assert result.measured.records_verified == 40
    assert result.measured.poisoned_records == 0
    assert result.meter.get("block_reasons") == {}
    assert result.cost.total_per_10k != float("inf")


def test_meter_sees_every_request():
    """攻击实现的每一次请求都必须过计量代理，无一漏网。"""
    result = run_once("open", ATTACKERS["naive"], RATES, items=40, page_size=20)
    # 40 条 / 每页 20 条 = 2 次取数请求；naive 不拉 bootstrap
    assert result.measured.requests == 2
    assert result.measured.total_bytes > 0
    assert result.measured.cpu_seconds > 0


def test_naive_blocked_on_signed_profile_with_attribution():
    """归因来自代理解析的响应体，不是攻击实现自报。"""
    result = run_once("api-signed", ATTACKERS["naive"], RATES, items=40, page_size=20)
    assert result.measured.records_verified == 0
    assert result.cost.total_per_10k == float("inf")
    assert result.primary_block_reason is not None


def test_signed_beats_naive_on_signed_profile():
    """阶梯的核心断言：api-signed 上必须爬到 L1 才采得到数据。"""
    naive = run_once("api-signed", ATTACKERS["naive"], RATES, items=40, page_size=20)
    signed = run_once("api-signed", ATTACKERS["signed"], RATES, items=40, page_size=20)
    assert not naive.succeeded
    assert signed.succeeded
    assert signed.measured.records_verified == 40


def test_blind_mode_poisons_silently():
    """blind 模式：HTTP 全 200，真值 0 条，且没有任何归因信息。

    这是本项目最独特的一项测量——只统计状态码的采集器会悄无声息地采走垃圾，
    而 R 和单位成本都会被严重低估。
    """
    result = run_once(
        "api-signed", ATTACKERS["naive"], RATES, items=40, page_size=20, mode="blind"
    )
    assert result.meter["status_counts"].get(200, 0) > 0
    assert result.meter["status_counts"].get(403, 0) == 0
    assert result.measured.records_returned == 40
    assert result.measured.records_verified == 0
    assert result.measured.poisoned_records == 40
    # 关键：拿不到任何失败信号
    assert result.meter.get("block_reasons") == {}
    assert result.primary_block_reason is None


def test_cheapest_viable_rung_on_cdn_standard():
    """cdn-standard 上 spoofed（L0）就够，爬到 L5 是纯浪费。

    这是项目要防的那个误判的直接证据。
    """
    spoofed = run_once("cdn-standard", ATTACKERS["spoofed"], RATES, items=40, page_size=20)
    traced = run_once("cdn-standard", ATTACKERS["traced"], RATES, items=40, page_size=20)
    assert spoofed.succeeded and traced.succeeded
    assert spoofed.cost.total_per_10k < traced.cost.total_per_10k


def test_browser_runs_site_js_and_costs_more_at_margin():
    """真浏览器跑站点自己的 sign.js 拿下 api-signed，且边际成本高于纯 HTTP。

    browser 不逆向签名——它在真实运行时里执行 signedFetch。所以它能过
    api-signed（L3 derived）就证明了这条"不逆向"的路径确实通。而它的边际
    成本应显著高于 signed（真浏览器的 CPU + 整页流量）。
    """
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        pytest.skip("未安装 playwright")

    browser = run_once("api-signed", ATTACKERS["browser"], RATES, items=40, page_size=20)
    signed = run_once("api-signed", ATTACKERS["signed"], RATES, items=40, page_size=20)
    assert browser.succeeded, f"browser 未采到数据: {browser.attacker_stderr[-3:]}"
    assert browser.measured.records_verified == 40
    # 真浏览器加载整页 + Chromium CPU，边际成本必然高于纯 HTTP 的 signed
    assert browser.cost.measured_per_10k > signed.cost.measured_per_10k
