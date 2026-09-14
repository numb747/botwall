"""Profile 加载。

Profile 是一份版本钉死的 YAML，描述某一类站点的防御组合。它是实验的自变量，
成本是因变量。所有结果都必须标注 profile 的 name + version，否则不可比。

靶场自身不产生随机密钥：salt、seed、指纹名单全部来自 profile 文件。
同一个 profile 在任何机器上跑出的结果必须一致。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .core import Strength

RANGE_ROOT = Path(__file__).resolve().parent.parent
PROFILE_DIR = RANGE_ROOT / "profiles"
FINGERPRINT_DIR = RANGE_ROOT / "fingerprints"


@dataclass(frozen=True)
class Profile:
    name: str
    version: int
    description: str
    form: str
    mode: str
    score_threshold: float
    captcha_trigger_score: float
    layers: dict[str, dict[str, Any]]
    source: Path

    @property
    def stamp(self) -> str:
        """用于标注实验结果的版本戳。"""
        return f"{self.name}@v{self.version}"

    def enabled_layers(self) -> list[str]:
        return sorted(
            layer_id
            for layer_id, cfg in self.layers.items()
            if cfg.get("strength", "off") != "off"
        )


def _resolve_fingerprints(ref: Any) -> dict[str, Any]:
    """把 options.fingerprints 的引用解析成实际数据。

    支持两种写法：
      fingerprints: builtin:demo        -> 读 fingerprints/demo.yaml
      fingerprints: {script_clients: …} -> 直接内联
    """
    if isinstance(ref, dict):
        return ref
    if isinstance(ref, str) and ref.startswith("builtin:"):
        path = FINGERPRINT_DIR / f"{ref.removeprefix('builtin:')}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"指纹集不存在: {path}")
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raise ValueError(f"无法解析 fingerprints 引用: {ref!r}")


def load_profile(name_or_path: str) -> Profile:
    path = Path(name_or_path)
    if not path.exists():
        path = PROFILE_DIR / f"{name_or_path}.yaml"
    if not path.exists():
        available = sorted(p.stem for p in PROFILE_DIR.glob("*.yaml"))
        raise FileNotFoundError(f"找不到 profile {name_or_path!r}；可用: {available}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    layers = raw.get("layers", {}) or {}

    for layer_id, cfg in layers.items():
        # strength 在这里归一化成规范字符串。YAML 1.1 把不加引号的 off 解析成
        # 布尔 False，不统一收口的话每个消费点都要各判一次。
        try:
            cfg["strength"] = Strength(cfg.get("strength", "off")).value
        except ValueError as exc:
            raise ValueError(f"{path.name}: 层 {layer_id} 的 strength 非法: {exc}") from exc

        options = cfg.get("options") or {}
        if "fingerprints" in options:
            options["fingerprints"] = _resolve_fingerprints(options["fingerprints"])
        cfg["options"] = options

    return Profile(
        name=raw.get("name", path.stem),
        version=int(raw.get("version", 1)),
        description=raw.get("description", ""),
        form=raw.get("form", "gate"),
        mode=raw.get("mode", "diagnostic"),
        score_threshold=float(raw.get("score_threshold", 1.0)),
        captcha_trigger_score=float(raw.get("captcha_trigger_score", 1.0)),
        layers=layers,
        source=path,
    )


def list_profiles() -> list[str]:
    return sorted(p.stem for p in PROFILE_DIR.glob("*.yaml"))
