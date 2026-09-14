"""tlsfront 的集成测试：真的起 TLS 服务，用真实客户端连。

单元测试（test_ja3.py）用手工拼的 ClientHello 覆盖解析逻辑。这里要证明的是
另一件事——**在真实 TLS 握手中，MemoryBIO 那套先截获再回放的做法确实可行，
且不同客户端的指纹确实互不相同、各自稳定**。这是 L2 从"读 header"变成真的
之后唯一需要成立的前提。
"""

from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tlsfront.certs import ensure_cert
from tlsfront.proxy import TlsFront

pytestmark = pytest.mark.e2e

CURL = shutil.which("curl")
NODE = shutil.which("node")


class _Echo(BaseHTTPRequestHandler):
    """把 tlsfront 注入的头回显出来，方便断言。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        body = json.dumps(
            {
                "ja3": self.headers.get("X-BW-JA3"),
                "ja3_string": self.headers.get("X-BW-JA3-String"),
                "sni": self.headers.get("X-BW-TLS-SNI"),
                "ua": self.headers.get("User-Agent", ""),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def front():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    certfile, keyfile = ensure_cert()
    with TlsFront(f"http://127.0.0.1:{upstream.server_address[1]}", certfile, keyfile, port=0) as f:
        time.sleep(0.2)
        yield f
    upstream.shutdown()


def fetch_python(front, headers: dict | None = None) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(f"{front.base_url}/probe", headers=headers or {})
    with urllib.request.urlopen(request, context=ctx, timeout=15) as response:
        return json.loads(response.read())


def fetch_curl(front, extra: list[str] | None = None) -> dict:
    result = subprocess.run(
        [str(CURL), "-sk", *(extra or []), f"{front.base_url}/probe"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.stdout.strip(), f"curl 无输出: {result.stderr[:200]}"
    return json.loads(result.stdout)


# --- 基本可行性 ---


def test_handshake_survives_clienthello_interception(front):
    """核心技巧的验证：ClientHello 被读走后，握手依然能正常完成。

    普通的 wrap_socket 做不到这一点——它拿不到已经被消费掉的第一个包。
    用 MemoryBIO 把原始字节回放进去才行。
    """
    result = fetch_python(front)
    assert result["ja3"], "没有注入 JA3"
    assert len(result["ja3"]) == 32, "JA3 应是 32 位十六进制 MD5"


def test_ja3_string_has_five_fields(front):
    parts = fetch_python(front)["ja3_string"].split(",")
    assert len(parts) == 5, f"JA3 字符串应有 5 段，实得 {len(parts)}"
    assert parts[0] == "771", "legacy_version 应为 0x0303"
    assert parts[1], "密码套件不能为空"


def test_same_client_is_stable(front):
    """同一客户端反复连，指纹必须完全一致。

    不稳定的指纹比没有指纹更糟：它会偶发地拦掉合法客户端，而且极难排查。
    """
    fingerprints = {fetch_python(front)["ja3"] for _ in range(4)}
    assert len(fingerprints) == 1, f"同一客户端指纹漂移: {fingerprints}"


def test_client_self_reported_ja3_is_overridden(front):
    """客户端自报的 X-BW-JA3 必须被丢弃。

    开发模式下允许自报是为了方便单测；一旦 tlsfront 在前面，这个头就只能
    由它说了算，否则整层防御形同虚设。
    """
    forged = "0" * 32
    result = fetch_python(front, {"X-BW-JA3": forged})
    assert result["ja3"] != forged, "伪造的 JA3 没有被覆盖"


# --- 不同客户端要能区分开 ---


@pytest.mark.skipif(CURL is None, reason="需要 curl")
def test_curl_differs_from_python(front):
    """不同 TLS 栈必须算出不同指纹——这正是 L2 能识别脚本客户端的依据。"""
    assert fetch_curl(front)["ja3"] != fetch_python(front)["ja3"]


@pytest.mark.skipif(CURL is None, reason="需要 curl")
def test_curl_is_stable(front):
    assert fetch_curl(front)["ja3"] == fetch_curl(front)["ja3"]


@pytest.mark.skipif(CURL is None, reason="需要 curl")
def test_changing_user_agent_does_not_change_fingerprint(front):
    """换 UA 换不掉 TLS 指纹 —— 这是交叉校验能成立的根本原因。

    单看 JA3 只能说"这不是浏览器"；而"UA 自称 Chrome、握手却是 curl 的形状"
    是强得多的信号，因为伪造方改不动握手。
    """
    plain = fetch_curl(front)
    disguised = fetch_curl(front, ["-A", "Mozilla/5.0 ... Chrome/142.0.0.0 Safari/537.36"])
    assert disguised["ua"].startswith("Mozilla/5.0")
    assert disguised["ja3"] == plain["ja3"], "改 UA 竟然改变了 TLS 指纹"


@pytest.mark.skipif(NODE is None, reason="需要 node")
def test_node_differs_from_others(front):
    script = (
        'const https=require("https");'
        f'https.get({{hostname:"127.0.0.1",port:{front.port},path:"/probe",'
        'rejectUnauthorized:false},r=>{let d="";r.on("data",c=>d+=c);'
        'r.on("end",()=>console.log(d));});'
    )
    result = subprocess.run([str(NODE), "-e", script], capture_output=True, text=True, timeout=20)
    assert result.stdout.strip(), f"node 无输出: {result.stderr[:200]}"
    node_ja3 = json.loads(result.stdout)["ja3"]
    assert node_ja3 != fetch_python(front)["ja3"]


def test_stats_record_every_fingerprint(front):
    """录制模式的数据来源：每个见过的指纹都要被记下来。"""
    fetch_python(front)
    assert front.stats.seen
    for ja3, entry in front.stats.seen.items():
        assert len(ja3) == 32
        assert entry["count"] >= 1
        assert entry["ja3_string"].count(",") == 4
