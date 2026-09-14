"""导出带标签的验证码数据集 —— 把"这个范式已经死了"从断言变成可验证的事实。

服务端生成的图片验证码有一个**结构性死穴**：生成它的程序同时知道答案。于是
任何人都能无限量地产出 (图像, 标签) 对——训练集是免费的，而且分布与线上
完全一致。

这个脚本把那句话变成一条命令：

    python -m tools.captcha_dataset --count 5000 --out /tmp/ds --difficulty paranoid

五千张带标签样本，文件名即标签，几分钟就能生成完。够训一个 CRNN 打到 95%+。
**加难度没用**，因为攻击方的训练数据和你的生成器是同一个东西；而加难度会让
人类失败率涨得比机器快——那条线是不能往上抬的。

这就是为什么这类验证码在面向消费者的大流量站点绝迹了。它在政企与传统行业
后台（招投标、司法文书、工商、教务、银行后台）仍大量存在，不是因为它安全，
而是因为那些系统没有换的动力。

用途仅限本地靶场自测。见 docs/04-scope.md。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from app import captcha_image


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="captcha_dataset", description="从靶场的生成器导出带标签数据集"
    )
    ap.add_argument("--count", type=int, default=1000, help="样本数")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument(
        "--difficulty", default="strict", choices=["lenient", "strict", "paranoid"]
    )
    ap.add_argument("--length", type=int, default=5, help="字符数")
    ap.add_argument("--seed-prefix", default="dataset", help="种子前缀，换它就换一批样本")
    args = ap.parse_args(argv)

    out = Path(args.out)
    (out / "images").mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    labels: list[dict] = []
    total_bytes = 0

    for index in range(args.count):
        seed = f"{args.seed_prefix}::{args.difficulty}::{index}"
        challenge = captcha_image.generate(seed, difficulty=args.difficulty, length=args.length)
        # 文件名即标签——这正是"训练集免费"的字面意思
        name = f"{index:06d}_{challenge.text}.png"
        (out / "images" / name).write_bytes(challenge.png)
        total_bytes += len(challenge.png)
        labels.append({"file": f"images/{name}", "label": challenge.text})

        if (index + 1) % 500 == 0:
            print(f"  {index + 1}/{args.count}", file=sys.stderr, flush=True)

    (out / "labels.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in labels), encoding="utf-8"
    )
    (out / "meta.json").write_text(
        json.dumps(
            {
                "count": args.count,
                "difficulty": args.difficulty,
                "length": args.length,
                "charset": captcha_image.CHARSET,
                "seed_prefix": args.seed_prefix,
                "note": "由靶场自身的生成器导出。标签免费，这正是该范式的结构性死穴。",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    elapsed = time.perf_counter() - started
    print(
        f"\n导出 {args.count} 张（{args.difficulty}）到 {out}\n"
        f"  耗时 {elapsed:.1f}s，{args.count / elapsed:.0f} 张/秒\n"
        f"  共 {total_bytes / 1_048_576:.1f} MB，标签在文件名与 labels.jsonl 里\n"
        f"\n生成一份训练集的边际成本 ≈ {elapsed / args.count * 1000:.1f} ms/张。"
        f"\n攻击方拿到的训练数据分布与线上完全一致——这是无法靠加难度修补的结构问题。"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
