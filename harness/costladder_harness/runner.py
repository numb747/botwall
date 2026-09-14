"""编排一次运行：起靶场 -> 起计量代理 -> 跑攻击实现 -> 校验 -> 算成本。

攻击实现拿到的 CL_TARGET 指向计量代理，不是靶场。它不知道靶场的真实地址。

CPU 时间的取法
--------------
用 resource.getrusage(RUSAGE_CHILDREN) 的前后差值。这个计数器只统计**已回收**
的子进程，而靶场进程在整个测量期间一直活着、不会被回收，所以差值精确等于
攻击进程消耗的 CPU。不用墙钟是因为墙钟里混着计量代理的转发开销。
"""

from __future__ import annotations

import json
import os
import resource
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .cost import CostBreakdown, Declared, Measured, compute
from .meter import Meter
from .rates import Rates, load_rates

HARNESS_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = HARNESS_ROOT.parent
RANGE_ROOT = REPO_ROOT / "range"
ATTACKER_DIR = HARNESS_ROOT / "attackers"


# --- 攻击实现清单 ---


@dataclass(frozen=True)
class AttackerSpec:
    name: str
    entry: Path
    rung: int
    dev_hours: float
    note: str


def load_attackers(path: Path | None = None) -> dict[str, AttackerSpec]:
    target = path or (ATTACKER_DIR / "manifest.yaml")
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    specs: dict[str, AttackerSpec] = {}
    for name, cfg in (raw.get("attackers") or {}).items():
        entry = ATTACKER_DIR / cfg["entry"]
        if not entry.exists():
            raise FileNotFoundError(f"攻击实现 {name} 的入口不存在: {entry}")
        specs[name] = AttackerSpec(
            name=name,
            entry=entry,
            rung=int(cfg.get("rung", 0)),
            dev_hours=float(cfg.get("dev_hours", 0.0)),
            note=str(cfg.get("note", "")).strip(),
        )
    return specs


# --- 靶场进程 ---


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RangeServer:
    """把靶场作为子进程拉起来，用作上下文管理器。"""

    def __init__(
        self,
        profile: str,
        *,
        mode: str | None = None,
        form: str | None = None,
        python: str | None = None,
    ) -> None:
        self.profile = profile
        self.mode = mode
        self.form = form
        self.port = _free_port()
        self.python = python or sys.executable
        self._proc: subprocess.Popen | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "RangeServer":
        env = dict(os.environ, CL_PROFILE=self.profile)
        if self.mode:
            env["CL_MODE"] = self.mode
        if self.form:
            env["CL_FORM"] = self.form
        self._proc = subprocess.Popen(
            [self.python, "-m", "uvicorn", "app.main:app", "--port", str(self.port),
             "--log-level", "error"],
            cwd=RANGE_ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self._await_ready()
        return self

    def _await_ready(self, timeout: float = 20.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc and self._proc.poll() is not None:
                err = self._proc.stderr.read().decode() if self._proc.stderr else ""
                raise RuntimeError(f"靶场启动失败 (profile={self.profile}):\n{err}")
            try:
                with urllib.request.urlopen(f"{self.base_url}/", timeout=1) as resp:
                    if resp.status == 200:
                        return
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                time.sleep(0.15)
        raise TimeoutError(f"靶场在 {timeout}s 内未就绪 (profile={self.profile})")

    def __exit__(self, *exc) -> None:
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
            if self._proc.stderr:
                self._proc.stderr.close()


# --- 运行结果 ---


@dataclass
class RunResult:
    profile: str
    mode: str
    form: str
    attacker: str
    rung: int
    exit_code: int
    measured: Measured
    declared: Declared
    cost: CostBreakdown
    meter: dict[str, Any]
    attacker_stderr: list[str] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.measured.records_verified > 0

    @property
    def primary_block_reason(self) -> str | None:
        reasons = self.meter.get("block_reasons") or {}
        return next(iter(reasons), None)

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return {
            "profile": self.profile,
            "mode": self.mode,
            "form": self.form,
            "attacker": self.attacker,
            "rung": self.rung,
            "exit_code": self.exit_code,
            "measured": asdict(self.measured),
            "declared": asdict(self.declared),
            "cost": self.cost.to_dict(),
            "meter": self.meter,
            "primary_block_reason": self.primary_block_reason,
        }


# --- 主流程 ---


def run_once(
    profile: str,
    attacker: AttackerSpec,
    rates: Rates,
    *,
    items: int = 200,
    page_size: int = 20,
    mode: str | None = None,
    form: str | None = None,
    proxy_tier: str = "datacenter",
    timeout: float = 120.0,
) -> RunResult:
    verify_record = _load_verifier()

    with RangeServer(profile, mode=mode, form=form) as server, Meter(server.base_url) as meter:
        effective = _describe(server)

        env = dict(
            os.environ,
            CL_TARGET=meter.base_url,
            CL_ITEMS_WANTED=str(items),
            CL_PAGE_SIZE=str(page_size),
            # 攻击实现互相 import（signed 用 spoofed 的 UA），所以入口目录要在路径上
            PYTHONPATH=str(ATTACKER_DIR),
        )

        # 基线必须在启动攻击进程之前取。RUSAGE_CHILDREN 只累计已回收的子进程，
        # 而靶场进程此刻仍在运行，因此不会污染差值。
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        wall_start = time.perf_counter()

        proc = subprocess.Popen(
            [sys.executable, str(attacker.entry)],
            cwd=ATTACKER_DIR,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # communicate() 自己用 selector 同时排空两个管道，不会死锁。
        # 不要再另起线程读 stderr —— 两边会抢同一个 fd。
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            timed_out = True

        stderr_lines = stderr.decode(errors="replace").splitlines()
        if timed_out:
            stderr_lines.append(f"[harness] 超时 {timeout}s，已强杀")

        wall = time.perf_counter() - wall_start
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)

        returned, verified = _tally(stdout, verify_record)

        measured = Measured(
            requests=meter.stats.requests,
            total_bytes=meter.stats.total_bytes,
            cpu_seconds=round(cpu, 4),
            wall_seconds=round(wall, 3),
            records_returned=returned,
            records_verified=verified,
        )
        declared = Declared(dev_hours=attacker.dev_hours, note=attacker.note)

        return RunResult(
            profile=profile,
            mode=effective["mode"],
            form=effective["form"],
            attacker=attacker.name,
            rung=attacker.rung,
            exit_code=proc.returncode if proc.returncode is not None else -1,
            measured=measured,
            declared=declared,
            cost=compute(measured, declared, rates, proxy_tier=proxy_tier),
            meter=meter.stats.summary(),
            attacker_stderr=stderr_lines[-20:],
        )


def _tally(stdout: bytes, verify_record) -> tuple[int, int]:
    """统计吐出的记录数与**已验证为真**的记录数。

    这两个数必须分开。blind 模式下靶场返回 HTTP 200 + 投毒数据，只统计
    状态码会把投毒响应算成成功，从而高估通过率、低估重试放大系数 R，
    最终低估单位成本。
    """
    returned = verified = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        returned += 1
        if verify_record(record):
            verified += 1
    return returned, verified


def _describe(server: RangeServer) -> dict[str, str]:
    with urllib.request.urlopen(f"{server.base_url}/", timeout=5) as resp:
        body = json.loads(resp.read())
    return {"mode": body.get("mode", "?"), "form": body.get("form", "?")}


def _load_verifier():
    """借靶场的 verify_record 来判定记录真伪。

    harness 必须能分辨真值和投毒数据，而这个判定属于靶场的数据定义，
    不该在 harness 里复制一份——复制就会漂移。
    """
    if str(RANGE_ROOT) not in sys.path:
        sys.path.insert(0, str(RANGE_ROOT))
    from app.data import verify_record

    return verify_record


def scan(
    profiles: list[str],
    attackers: list[AttackerSpec],
    rates: Rates | None = None,
    **kwargs,
) -> list[RunResult]:
    """对 profile × 攻击实现的笛卡尔积逐个跑一遍。"""
    rates = rates or load_rates()
    results: list[RunResult] = []
    for profile in profiles:
        for attacker in attackers:
            results.append(run_once(profile, attacker, rates, **kwargs))
    return results
