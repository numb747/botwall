"""测试共用设施。

make_probe 原来只在 test_layers.py 里，后来 test_captcha_image.py 也要用。
跨测试文件 import 是脆的（依赖 rootdir 和 sys.path 的巧合），抽到 conftest
才是 pytest 的正道。
"""

from __future__ import annotations

import time

import pytest

from app.core import Probe


def build_probe(**overrides) -> Probe:
    """构造一个 Probe。层只看得见 Probe，所以单测不需要起 HTTP 服务。"""
    base = dict(
        method="GET",
        path="/api/items",
        query={"limit": "20", "offset": "0"},
        headers={},
        cookies={},
        body=b"",
        client_ip="203.0.113.10",
        received_at=time.time(),
    )
    base.update(overrides)
    base["headers"] = {k.lower(): v for k, v in base["headers"].items()}
    return Probe(**base)


@pytest.fixture
def make_probe():
    return build_probe
