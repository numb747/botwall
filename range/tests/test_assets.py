"""页面资产生成器的测试。

核心是确定性：同一个资产在任何机器上都必须得到逐字节相同的内容，否则
browser 的流量成本不可复现，交叉点数字就没有意义。
"""

from __future__ import annotations

import gzip

from app import assets


def test_asset_is_deterministic():
    assert assets.asset_bytes("vendor.js") == assets.asset_bytes("vendor.js")


def test_assets_differ_by_name():
    assert assets.asset_bytes("vendor.js") != assets.asset_bytes("app.js")


def test_asset_size_matches_table():
    # 默认权重 1.0 下，字节数应等于表里的 KB 值
    assert len(assets.asset_bytes("app.css")) == 45 * 1024


def test_assets_are_incompressible():
    """资产必须压不动——否则计量到的字节数会高于真实过线量。"""
    raw = assets.asset_bytes("vendor.js")
    packed = gzip.compress(raw)
    # 伪随机流：压缩后不应明显变小（留一点 gzip 头部余量）
    assert len(packed) > len(raw) * 0.98


def test_weight_scales_all_assets(monkeypatch):
    monkeypatch.setenv("BW_PAGE_WEIGHT", "2.0")
    assert len(assets.asset_bytes("app.css")) == 45 * 1024 * 2
    monkeypatch.setenv("BW_PAGE_WEIGHT", "0")
    assert assets.asset_bytes("app.css") == b""


def test_total_page_weight():
    assert assets.total_page_kb() == sum(kb for kb, _ in assets._ASSET_KB.values())
