"""计量反向代理 —— 成本核算的信任根。

攻击实现拿到的 BW_TARGET 指向本代理，而不是靶场。它不知道靶场的真实地址，
因此**无法绕过计量**。所有字节数、请求数、状态码都由代理记账，不接受自报。

这是本项目与现有工作的一个实质区别：现有基准普遍是"作者在论文里写我们花了
$X"——不可复现、不可比较。把计量放在 harness 层强制执行，数字才有意义。

为什么不用墙钟算算力成本
------------------------
代理自身的转发开销会混进墙钟。算力成本改用**攻击进程自己的 CPU 时间**
（wait4 拿 rusage），与代理开销无关。墙钟只作为诊断量上报。
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

#: 转发时必须丢弃的逐跳头。Host 由 urllib 依据 upstream 重建；
#: Accept-Encoding 保持透传，因为压缩与否直接影响代理流量成本。
_HOP_BY_HOP = {"host", "connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade"}


@dataclass
class RequestRecord:
    method: str
    path: str
    status: int
    request_bytes: int
    response_bytes: int
    duration_ms: float
    #: 从 403 响应里解出的归因原因码。由代理解析，不是攻击实现自报——
    #: 攻击实现完全可以谎报自己被哪一层拦了。
    block_reasons: tuple[str, ...] = ()


@dataclass
class MeterStats:
    records: list[RequestRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, record: RequestRecord) -> None:
        with self._lock:
            self.records.append(record)

    @property
    def requests(self) -> int:
        return len(self.records)

    @property
    def total_bytes(self) -> int:
        return sum(r.request_bytes + r.response_bytes for r in self.records)

    @property
    def status_counts(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for r in self.records:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts

    @property
    def block_reason_counts(self) -> dict[str, int]:
        """被哪些原因拦了多少次。归因的权威来源。"""
        counts: dict[str, int] = {}
        for r in self.records:
            for reason in r.block_reasons:
                counts[reason] = counts.get(reason, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def summary(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "total_bytes": self.total_bytes,
            "bytes_per_request": round(self.total_bytes / self.requests, 1)
            if self.requests
            else 0.0,
            "status_counts": self.status_counts,
            "block_reasons": self.block_reason_counts,
            "median_duration_ms": _median([r.duration_ms for r in self.records]),
        }


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return round(ordered[mid], 2)
    return round((ordered[mid - 1] + ordered[mid]) / 2, 2)


def _header_bytes(headers) -> int:
    return sum(len(str(k)) + len(str(v)) + 4 for k, v in headers.items())


def _extract_reasons(payload: bytes) -> tuple[str, ...]:
    """从 diagnostic 模式的 403 响应体里解出原因码。

    blind 模式下响应是 200 + 投毒数据，这里自然解不出东西——这正是
    blind 模式要测的：没有归因帮助时，定位一次失败要花多久。
    """
    if not payload or not payload.lstrip().startswith(b"{"):
        return ()
    try:
        body = json.loads(payload)
    except ValueError:
        return ()
    if not isinstance(body, dict):
        return ()
    return tuple(
        str(b.get("reason"))
        for b in body.get("blocked_by", [])
        if isinstance(b, dict) and b.get("reason")
    )


def _make_handler(upstream: str, stats: MeterStats) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "botwallMeter/0.1"

        def log_message(self, *args) -> None:  # 静音：计量数据走 stats，不走 stderr
            pass

        def do_GET(self) -> None:
            self._proxy("GET")

        def do_POST(self) -> None:
            self._proxy("POST")

        def do_HEAD(self) -> None:
            self._proxy("HEAD")

        def _proxy(self, method: str) -> None:
            started = time.perf_counter()
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None

            request_bytes = (
                len(method) + len(self.path) + 12 + _header_bytes(self.headers) + (length or 0)
            )

            forwarded = {
                k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP
            }
            req = urllib.request.Request(
                f"{upstream}{self.path}", data=body, headers=forwarded, method=method
            )

            try:
                with urllib.request.urlopen(req) as resp:
                    status, headers, payload = resp.status, resp.headers, resp.read()
            except urllib.error.HTTPError as exc:
                status, headers, payload = exc.code, exc.headers, exc.read()
            except urllib.error.URLError as exc:
                status, headers, payload = 502, {}, str(exc).encode()

            response_bytes = len(payload) + _header_bytes(headers) + 15

            stats.add(
                RequestRecord(
                    method=method,
                    path=self.path.split("?")[0],
                    status=status,
                    request_bytes=request_bytes,
                    response_bytes=response_bytes,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    block_reasons=_extract_reasons(payload),
                )
            )

            self.send_response(status)
            for key, value in (headers.items() if headers else []):
                if key.lower() in _HOP_BY_HOP or key.lower() == "content-length":
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(payload)

    return Handler


class Meter:
    """在后台线程里跑的计量代理。用作上下文管理器。"""

    def __init__(self, upstream: str, host: str = "127.0.0.1", port: int = 0) -> None:
        self.upstream = upstream.rstrip("/")
        self.stats = MeterStats()
        self._server = ThreadingHTTPServer((host, port), _make_handler(self.upstream, self.stats))
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "Meter":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
