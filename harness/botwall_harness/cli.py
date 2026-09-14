"""命令行入口。

    botwall scan                          全 profile × 全攻击实现
    botwall scan -p api-signed -a signed  指定组合
    botwall scan --mode blind             覆盖响应模式，测投毒与排障成本
    botwall scan --proxy-tier residential 换代理档位重算
    botwall rates                         看当前价格表
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .rates import load_rates
from .report import as_json, decision_table
from .runner import RANGE_ROOT, load_attackers, run_once


def _range_profiles() -> list[str]:
    return sorted(p.stem for p in (RANGE_ROOT / "profiles").glob("*.yaml"))


def cmd_scan(args: argparse.Namespace) -> int:
    rates = load_rates(args.rates)
    if args.annual_records is not None:
        import dataclasses

        rates = dataclasses.replace(rates, annual_records=args.annual_records)
    specs = load_attackers()

    profiles = args.profile or _range_profiles()
    unknown = [p for p in profiles if p not in _range_profiles()]
    if unknown:
        print(f"未知 profile: {unknown}；可用: {_range_profiles()}", file=sys.stderr)
        return 2

    names = args.attacker or list(specs)
    unknown = [a for a in names if a not in specs]
    if unknown:
        print(f"未知攻击实现: {unknown}；可用: {sorted(specs)}", file=sys.stderr)
        return 2

    results = []
    total = len(profiles) * len(names)
    done = 0
    for profile in profiles:
        for name in names:
            done += 1
            print(f"[{done}/{total}] {profile} × {name} ...", file=sys.stderr, flush=True)
            results.append(
                run_once(
                    profile,
                    specs[name],
                    rates,
                    items=args.items,
                    page_size=args.page_size,
                    mode=args.mode,
                    form=args.form,
                    proxy_tier=args.proxy_tier,
                )
            )

    print(decision_table(results, rates))

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(as_json(results, rates), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n结果已写入 {out}", file=sys.stderr)
    return 0


def cmd_rates(args: argparse.Namespace) -> int:
    rates = load_rates(args.rates)
    print(json.dumps(rates.to_dict(), ensure_ascii=False, indent=2))
    print(
        f"\n人工打码地板线: ${rates.human_floor_usd_per_solve:.5f}/次"
        f"  (= ${rates.human_floor_usd_per_solve * 10000:,.2f}/万条)"
    )
    return 0


def cmd_attackers(_: argparse.Namespace) -> int:
    for name, spec in sorted(load_attackers().items(), key=lambda kv: kv[1].rung):
        print(f"L{spec.rung}  {name:<12} 申报工时 {spec.dev_hours:>5.1f}h")
        if spec.note:
            for line in spec.note.splitlines():
                print(f"      {line.strip()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="botwall", description="采集成本阶梯扫描")
    sub = ap.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="跑 profile × 攻击实现，输出决策表")
    scan.add_argument("-p", "--profile", action="append", help="可重复；默认全部")
    scan.add_argument("-a", "--attacker", action="append", help="可重复；默认全部")
    scan.add_argument("-n", "--items", type=int, default=200, help="目标采集条数")
    scan.add_argument("--page-size", type=int, default=20)
    scan.add_argument("--mode", choices=["diagnostic", "blind"], help="覆盖 profile 的响应模式")
    scan.add_argument("--form", choices=["gate", "score"], help="覆盖 profile 的判定形态")
    scan.add_argument(
        "--proxy-tier",
        default="datacenter",
        help="代理档位：none / datacenter / residential / mobile",
    )
    scan.add_argument("--rates", help="价格表路径，默认 harness/rates.yaml")
    scan.add_argument(
        "--annual-records",
        type=int,
        help="覆盖年采集量，用于观察 signed 与 browser 的成本交叉点",
    )
    scan.add_argument("-o", "--out", help="把完整结果写成 JSON")
    scan.set_defaults(func=cmd_scan)

    rates = sub.add_parser("rates", help="显示当前价格表")
    rates.add_argument("--rates", help="价格表路径")
    rates.set_defaults(func=cmd_rates)

    attackers = sub.add_parser("attackers", help="列出攻击实现及其申报工时")
    attackers.set_defaults(func=cmd_attackers)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
