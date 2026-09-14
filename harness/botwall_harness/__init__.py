"""botwall harness —— 成本核算与阶梯扫描。

    from botwall_harness import load_rates, load_attackers, run_once, decision_table
"""

from .cost import CostBreakdown, Declared, Measured, compute
from .meter import Meter, MeterStats
from .rates import Rates, load_rates
from .report import as_json, as_jsonl, decision_table
from .runner import AttackerSpec, RangeServer, RunResult, load_attackers, run_once, scan

__version__ = "0.1.0"

__all__ = [
    "AttackerSpec",
    "CostBreakdown",
    "Declared",
    "Measured",
    "Meter",
    "MeterStats",
    "RangeServer",
    "Rates",
    "RunResult",
    "as_json",
    "as_jsonl",
    "compute",
    "decision_table",
    "load_attackers",
    "load_rates",
    "run_once",
    "scan",
]
