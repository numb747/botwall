"""自动录制本机各客户端的真实 JA3，生成指纹集。

`python -m tlsfront record` 是交互式的——起个代理，等你手工用各个客户端去连。
这个脚本把能自动化的部分自动化：它起 tlsfront，然后依次驱动本机上找得到的
每个客户端各连一次，最后导出 YAML。

    python -m tools.record_fingerprints --out ../fingerprints/local.yaml

能自动录的：Python ssl、curl、Node https、Playwright Chromium（真浏览器）。
录不到的：你本机安装的 Chrome / Firefox / Safari 本体，以及 curl_cffi 的各个
impersonate 目标。那些要么需要图形界面，要么需要额外装包——用交互式的
`python -m tlsfront record` 补录，两者生成的格式一样，可以合并。

为什么指纹集必须自己录
----------------------
JA3 随客户端版本变化。仓库里写死的真实指纹几个月就过期，而**过期的指纹会让
真浏览器也被判为"不在白名单"**——L2 的测量结果因此系统性偏高，而且症状是
"偶尔拦错人"，极难排查。所以每条记录都强制带上版本号。
"""

from __future__ import annotations

import argparse
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tlsfront.certs import ensure_cert
from tlsfront.proxy import TlsFront


class _Sink(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _version(command: list[str], pattern: str = "") -> str:
    try:
        out = subprocess.run(command, capture_output=True, text=True, timeout=10)
        line = (out.stdout or out.stderr).strip().splitlines()[0]
        return line[:80]
    except (OSError, subprocess.SubprocessError, IndexError):
        return pattern or "unknown"


# --- 各客户端的驱动 ---


def _importable(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def probe_python(url: str, port: int) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(url, headers={"User-Agent": "python-urllib"})
    with urllib.request.urlopen(request, context=ctx, timeout=15):
        pass
    return f"python-urllib / {ssl.OPENSSL_VERSION}"


def probe_curl(url: str, port: int) -> str:
    subprocess.run(
        [shutil.which("curl") or "curl", "-sk", "-A", "curl-probe", url],
        capture_output=True, timeout=20, check=True,
    )
    return _version([shutil.which("curl") or "curl", "--version"])


def probe_node(url: str, port: int) -> str:
    script = (
        'const https=require("https");'
        f'https.get({{hostname:"127.0.0.1",port:{port},path:"/probe",'
        'rejectUnauthorized:false,headers:{"User-Agent":"node-probe"}},'
        "r=>{r.resume();r.on('end',()=>process.exit(0));});"
    )
    node = shutil.which("node") or "node"
    subprocess.run([node, "-e", script], capture_output=True, timeout=20, check=True)
    return f"node {_version([node, '--version'])}"


def probe_chromium(url: str, port: int) -> str:
    """真浏览器。这是整份指纹集里最有价值的一条——白名单就是靠它建立的。"""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded")
        version = page.evaluate("navigator.userAgent")
        browser.close()
    return f"chromium (playwright headless) / {version[:70]}"


#: (名字, 驱动函数, 本机是否可用)。驱动函数统一签名 (url, port)。
PROBES = [
    ("python-urllib", probe_python, lambda: True),
    ("curl", probe_curl, lambda: shutil.which("curl") is not None),
    ("node-https", probe_node, lambda: shutil.which("node") is not None),
    ("chromium-headless", probe_chromium, lambda: _importable("playwright")),
]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="record_fingerprints")
    ap.add_argument("--out", default="../fingerprints/local.yaml")
    args = ap.parse_args(argv)

    sink = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    certfile, keyfile = ensure_cert()

    recorded: list[dict] = []
    with TlsFront(f"http://127.0.0.1:{sink.server_address[1]}", certfile, keyfile, port=0) as front:
        time.sleep(0.3)
        url = f"{front.base_url}/probe"

        for name, probe, available in PROBES:
            if not available():
                print(f"  跳过 {name}（本机不可用）", file=sys.stderr)
                continue
            before = set(front.stats.seen)
            try:
                version = probe(url, front.port)
            except Exception as exc:  # noqa: BLE001 —— 某个客户端失败不该中断整轮
                print(f"  {name} 失败: {type(exc).__name__}: {exc}", file=sys.stderr)
                continue
            new = set(front.stats.seen) - before
            if not new:
                print(f"  {name} 没有产生新指纹（可能与前一个客户端相同）", file=sys.stderr)
                continue
            for ja3 in new:
                recorded.append(
                    {
                        "name": name,
                        "ja3": ja3,
                        "ja3_string": front.stats.seen[ja3]["ja3_string"],
                        "version": version,
                    }
                )
                print(f"  {name:<20} {ja3}", file=sys.stderr)

    sink.shutdown()

    if not recorded:
        print("没有录到任何指纹。", file=sys.stderr)
        return 1

    # 浏览器进白名单，脚本客户端进黑名单——这个划分是 L2 判定的依据
    browsers = [r for r in recorded if "chromium" in r["name"] or "firefox" in r["name"]]
    scripts = [r for r in recorded if r not in browsers]

    stamp = time.strftime("%Y-%m-%d")
    lines = [
        f"# 由 `python -m tools.record_fingerprints` 于 {stamp} 在本机录制。",
        "#",
        "# ⚠️ JA3 随客户端版本变化。过期的指纹会让真浏览器也被判为不在白名单，",
        "#    L2 的结果因此系统性偏高，症状还是\"偶尔拦错人\"。",
        "#    每条都带了录制时的版本号——换机器或升级客户端后请重录。",
        "",
        "# ja3 -> 客户端名。命中即判定为脚本库，不看强度档。",
        "script_clients:",
    ]
    for row in scripts:
        lines.append(f"  # {row['version']}")
        lines.append(f"  # ja3_string: {row['ja3_string']}")
        lines.append(f'  {row["ja3"]}: "{row["name"]}"')
        lines.append("")

    lines += [
        "# ja3 -> 浏览器族。strict 档要求命中本表；paranoid 档还要求与 UA 一致。",
        "browsers:",
    ]
    for row in browsers:
        lines.append(f"  # {row['version']}")
        lines.append(f"  # ja3_string: {row['ja3_string']}")
        lines.append(f'  {row["ja3"]}: "chrome"')
        lines.append("")
    if not browsers:
        lines.append("  # 本机没录到任何真浏览器指纹。用 `python -m tlsfront record`")
        lines.append("  # 手工补录你本机的 Chrome / Firefox / Safari。")
        lines.append("  {}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n录到 {len(recorded)} 个指纹，已写入 {out}")
    print("在 profile 里把 fingerprints 改成 builtin:<文件名> 即可启用。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
