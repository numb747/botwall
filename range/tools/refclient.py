"""参考客户端 —— 靶场的"标准答案"。

它直接 import 服务端的 signing 模块，所以必然签对。用途只有一个：
**验证靶场本身是通的**。它不是攻击实现，也不该被当成攻击实现的起点——
攻击侧的任务恰恰是在不看 signing.py 的前提下，从抓包结果复现出同样的行为。

用法：
    cd range
    .venv/bin/python -m tools.refclient --port 8901
    .venv/bin/python -m tools.refclient --port 8901 --profile hardened
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from app import signing


def canonical_query(params: dict[str, str]) -> str:
    return "&".join(f"{k}={params[k]}" for k in sorted(params))


def fake_env(user_agent: str) -> str:
    """一份自洽的环境快照。

    注意它是**手工拼出来的**，不是真浏览器采集的。L4 的 paranoid 档之所以
    仍然放行它，是因为这里的每个字段都刻意保持了互相一致——这正好说明
    环境检测的门槛在"自洽"而非"真实"，也说明伪造成本随检查项数量线性上升。
    """
    env = {
        "userAgent": user_agent,
        "platform": "Win32",
        "languages": ["zh-CN", "zh"],
        "hardwareConcurrency": 8,
        "webdriver": False,
        "webglVendor": "Google Inc.",
        "webglRenderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
        "canvasHash": "3f9a1c74be205d81",
        "windowKeys": [],
        "collectMs": 14.3,
    }
    return base64.b64encode(json.dumps(env).encode()).decode()


def human_trace() -> str:
    """类人轨迹：间隔不等、速度先加后减、路径是弧线。三者缺一不可。"""
    gaps = [18.0, 31.0, 12.0, 44.0, 21.0, 9.0, 37.0, 26.0, 15.0, 40.0, 23.0, 11.0]
    speeds = [0.3, 0.9, 2.1, 3.0, 3.4, 3.1, 2.2, 1.3, 0.7, 0.4, 0.25, 0.15]
    curve = [0.55, 0.45, 0.30, 0.15, 0.0, -0.18, -0.32, -0.42, -0.5, -0.55, -0.6, -0.6]
    events, t, x, y = [], 0.0, 100.0, 200.0
    for gap, speed, c in zip(gaps, speeds, curve):
        dist = gap * speed
        t += gap
        x += dist
        y += dist * c
        events.append({"t": round(t, 2), "type": "mousemove", "x": round(x), "y": round(y)})
    for type_, gap in (("mousedown", 80.0), ("mouseup", 95.0), ("click", 3.0)):
        t += gap
        events.append({"t": round(t, 2), "type": type_, "x": round(x), "y": round(y)})
    return base64.b64encode(json.dumps(events).encode()).decode()


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"


def get(url: str, headers: dict[str, str]) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8900)
    ap.add_argument("--ja3", default="PLACEHOLDER_JA3_CHROME_142")
    ap.add_argument("--limit", type=int, default=3)
    ap.add_argument(
        "--naive",
        action="store_true",
        help="模拟一个什么都不做的采集器：只发一个裸 GET。用来看归因输出。",
    )
    args = ap.parse_args()
    base = f"http://{args.host}:{args.port}"

    meta = get(f"{base}/", {})[1]
    print(f"profile   : {meta['profile']}  ({meta['mode']}/{meta['form']})")
    print(f"启用的层  : {', '.join(meta['enabled_layers']) or '（无）'}")

    path = "/api/items"
    params = {"limit": str(args.limit), "offset": "0"}

    if args.naive:
        print("客户端    : naive（裸 GET，无任何头）")
        headers: dict[str, str] = {}
    else:
        boot = get(f"{base}/api/bootstrap", {})[1]
        salt_mode = boot.get("salt_mode")
        print(f"salt_mode : {salt_mode}")

        ts = str(int(time.time() * 1000))
        nonce = secrets.token_hex(12)
        env = fake_env(UA)
        headers = {
            "User-Agent": UA,
            "X-CL-JA3": args.ja3,
            "X-CL-Session": secrets.token_hex(8),
            "X-CL-Trace": human_trace(),
            "X-CL-Env": env,
        }
        if salt_mode:
            headers["X-CL-Ts"] = ts
            headers["X-CL-Nonce"] = nonce
            headers["X-CL-Sign"] = signing.compute(
                salt_mode=salt_mode,
                seed=boot["seed"],
                static_salt="cl-demo-salt",
                env_snapshot=env,
                method="GET",
                path=path,
                canonical_query=canonical_query(params),
                ts=ts,
                nonce=nonce,
            )

    url = f"{base}{path}?{urllib.parse.urlencode(params)}"
    status, body = get(url, headers)
    print(f"\nGET {path} -> HTTP {status}")

    if status == 200:
        from app.data import verify_record

        items = body.get("items", [])
        genuine = sum(1 for r in items if verify_record(r))
        print(f"取到 {len(items)} 条，其中真值 {genuine} 条")
        if genuine < len(items):
            print("⚠️  收到投毒数据：HTTP 200 但内容是假的。")
            print("   这就是 blind 模式——只统计状态码的采集器会悄无声息地采走垃圾。")
        else:
            for record in items[:3]:
                print("   ", record)
    else:
        for blocked in body.get("blocked_by", []):
            rung = blocked["ladder_rung"]
            # rung 0 是最值得讲清楚的一档：被拦了，但不需要离开阶梯 L0。
            # 把它打印成"需要爬到 L0"会误导人往上爬，而那正是最贵的误判。
            advice = (
                "换个客户端即可，不必升级架构（成本增量≈0）"
                if rung == 0
                else f"需要爬到成本阶梯 L{rung}"
            )
            print(f"  被 {blocked['layer']} 拦住：{blocked['reason']}  -> {advice}")
            if blocked.get("detail"):
                print(f"     {json.dumps(blocked['detail'], ensure_ascii=False)}")
        if body.get("challenge"):
            print(f"  下发了挑战：{body['challenge']}")


if __name__ == "__main__":
    main()
