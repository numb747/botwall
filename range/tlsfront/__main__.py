"""tlsfront 命令行。

    # 起代理，上游指向已在跑的靶场
    python -m tlsfront --upstream http://127.0.0.1:8900 --port 8443

    # 录制自己机器上各个客户端的真实 JA3，写成指纹集
    python -m tlsfront record --out ../fingerprints/local.yaml
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .certs import ensure_cert
from .proxy import TlsFront


def cmd_serve(args: argparse.Namespace) -> int:
    certfile, keyfile = ensure_cert()
    with TlsFront(args.upstream, certfile, keyfile, port=args.port, verbose=True) as front:
        print(f"tlsfront 监听 {front.base_url}  ->  {args.upstream}")
        print("自签证书，客户端需要跳过校验（curl -k / verify=False）")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    """录制模式：起代理，等你用各个客户端来连，然后导出指纹集。"""
    certfile, keyfile = ensure_cert()
    with TlsFront(args.upstream, certfile, keyfile, port=args.port, verbose=True) as front:
        print(f"tlsfront 录制中，监听 {front.base_url}")
        print("现在用你要录的每个客户端各访问一次（真 Chrome、真 Firefox、")
        print("requests、curl_cffi 的各个 impersonate 目标……），Ctrl-C 结束。")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print()

        if not front.stats.seen:
            print("没有录到任何指纹。", file=sys.stderr)
            return 1

        lines = [
            "# 由 `python -m tlsfront record` 录制。",
            "# ⚠️ 请手工填写每条的客户端名与**完整版本号**——没有版本号的指纹集",
            "#    几个月后就无法判断是否还有效。",
            "",
            "script_clients: {}",
            "",
            "browsers:",
        ]
        for ja3, entry in sorted(front.stats.seen.items(), key=lambda kv: -kv[1]["count"]):
            agents = entry["user_agents"] or ["(未知客户端)"]
            lines.append(f"  # 命中 {entry['count']} 次 | UA: {agents[0][:100]}")
            lines.append(f"  # ja3_string: {entry['ja3_string']}")
            lines.append(f'  {ja3}: "TODO-填写客户端名与版本"')
            lines.append("")

        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines), encoding="utf-8")
        print(f"录到 {len(front.stats.seen)} 个不同指纹，已写入 {out}")
        print("请填好 TODO 后，在 profile 里把 fingerprints 改成 builtin:local")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tlsfront", description="TLS 指纹前置代理")
    ap.add_argument("--upstream", default="http://127.0.0.1:8900", help="靶场地址")
    ap.add_argument("--port", type=int, default=8443)
    sub = ap.add_subparsers(dest="command")

    record = sub.add_parser("record", help="录制本机各客户端的真实 JA3")
    record.add_argument("--upstream", default="http://127.0.0.1:8900")
    record.add_argument("--port", type=int, default=8443)
    record.add_argument("--out", default="../fingerprints/local.yaml")
    record.set_defaults(func=cmd_record)

    args = ap.parse_args(argv)
    if not hasattr(args, "func"):
        args.func = cmd_serve
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
