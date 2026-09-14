"""指纹集文件的测试。

格式错了不会报错，只会让 L2 静默失效——白名单空了，所有客户端都被判"不在
白名单"，或者更糟：黑名单空了，脚本客户端畅通无阻。所以这里守住结构。
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.config import FINGERPRINT_DIR, _resolve_fingerprints
from tlsfront import ja3

SETS = sorted(FINGERPRINT_DIR.glob("*.yaml"))


def test_fingerprint_sets_exist():
    assert SETS, f"{FINGERPRINT_DIR} 下没有任何指纹集"


@pytest.mark.parametrize("path", SETS, ids=lambda p: p.name)
def test_set_parses_and_has_both_tables(path: Path):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    assert "script_clients" in data, "缺少 script_clients 表"
    assert "browsers" in data, "缺少 browsers 表"
    for table in ("script_clients", "browsers"):
        assert isinstance(data[table] or {}, dict), f"{table} 不是映射"


@pytest.mark.parametrize("path", SETS, ids=lambda p: p.name)
def test_no_ja3_appears_in_both_tables(path: Path):
    """同一个指纹不能既是脚本库又是浏览器——那样判定结果取决于代码顺序。"""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    overlap = set(data.get("script_clients") or {}) & set(data.get("browsers") or {})
    assert not overlap, f"指纹同时出现在两张表里: {overlap}"


@pytest.mark.parametrize("path", SETS, ids=lambda p: p.name)
def test_browser_families_are_recognised(path: Path):
    """浏览器族取值必须是 L2 认得的那几个，否则 paranoid 档的交叉校验永远失败。"""
    from tlsfront.ja3 import ClientHello  # noqa: F401 —— 仅为确保模块可导入

    known = {"chrome", "firefox", "safari", "edge", "opera"}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for value in (data.get("browsers") or {}).values():
        assert value in known, f"未知浏览器族 {value!r}，可用: {sorted(known)}"


def test_recorded_example_holds_real_fingerprints():
    """参考样例里的必须是真 JA3（32 位十六进制），不是占位符。"""
    path = FINGERPRINT_DIR / "recorded-example.yaml"
    if not path.exists():
        pytest.skip("没有参考样例")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = {**(data.get("script_clients") or {}), **(data.get("browsers") or {})}
    assert entries, "参考样例是空的"
    for key in entries:
        assert len(key) == 32 and all(c in "0123456789abcdef" for c in key), (
            f"{key!r} 不是 JA3（32 位十六进制 MD5）"
        )


def test_demo_set_is_openly_placeholder():
    """demo.yaml 是占位符，必须一眼看得出来，不能被误当成真数据引用。"""
    data = yaml.safe_load((FINGERPRINT_DIR / "demo.yaml").read_text(encoding="utf-8")) or {}
    entries = {**(data.get("script_clients") or {}), **(data.get("browsers") or {})}
    assert all("PLACEHOLDER" in key for key in entries), "占位符没有显式标记"


def test_builtin_reference_resolves():
    resolved = _resolve_fingerprints("builtin:recorded-example")
    assert resolved["browsers"]


def test_unknown_builtin_raises():
    with pytest.raises(FileNotFoundError):
        _resolve_fingerprints("builtin:does-not-exist")


def test_recorded_ja3_matches_its_ja3_string():
    """注释里的 ja3_string 必须真的哈希成那个 ja3——否则记录是错的。"""
    import hashlib
    import re

    path = FINGERPRINT_DIR / "recorded-example.yaml"
    if not path.exists():
        pytest.skip("没有参考样例")
    text = path.read_text(encoding="utf-8")
    pairs = re.findall(r"# ja3_string: (.+)\n\s+([0-9a-f]{32}):", text)
    assert pairs, "参考样例里没有可校验的 ja3_string 注释"
    for ja3_string, expected in pairs:
        actual = hashlib.md5(ja3_string.strip().encode()).hexdigest()
        assert actual == expected, f"ja3_string 与 ja3 对不上:\n  {ja3_string[:60]}..."
