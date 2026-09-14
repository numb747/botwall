"""TLS 终结代理 —— 在握手完成前截下 ClientHello，算出 JA3，再注入给靶场。

为什么要这么绕
--------------
JA3 的原料只存在于握手的第一个包里。要同时做到「拿到原始字节」和「正常完成
TLS 握手」，就不能用普通的 `ssl.wrap_socket`——那会把 ClientHello 直接吃掉。

做法是用 `ssl.MemoryBIO`：

    1. 从裸 socket 读出第一条 TLS 记录（ClientHello），**只读不消费握手状态**
    2. 解析它，算 JA3
    3. 把这段字节原样喂回 incoming BIO，再驱动握手
    4. 握手成功后，把解密出的 HTTP 请求转发给靶场，并强制覆盖 X-BW-JA3

第 4 步的「强制覆盖」是关键：客户端自己发来的 X-BW-JA3 一律丢弃。开发模式下
允许自报是为了方便单测，一旦 tlsfront 在前面，这个头就只能由它说了算。
"""

from __future__ import annotations

import re
import selectors
import socket
import ssl
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .ja3 import ClientHelloError, parse_client_hello, record_length

#: 客户端自报的这些头一律丢弃，由本代理重写
_OVERRIDDEN = {"x-bw-ja3", "x-bw-ja3-string", "x-bw-tls-sni"}
#: 逐跳头，不转发
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade"}

_REQUEST_LINE = re.compile(rb"^([A-Z]+) ([^ ]+) HTTP/1\.[01]\r\n")


@dataclass
class FrontStats:
    """看到过哪些指纹。用于 `record` 子命令录制自己的指纹集。"""

    seen: dict[str, dict] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def note(self, ja3: str, ja3_string: str, user_agent: str) -> None:
        with self._lock:
            entry = self.seen.setdefault(
                ja3, {"ja3_string": ja3_string, "count": 0, "user_agents": []}
            )
            entry["count"] += 1
            if user_agent and user_agent not in entry["user_agents"]:
                entry["user_agents"].append(user_agent)


class TlsFront:
    """监听 TLS，转发明文 HTTP 给上游靶场。"""

    def __init__(
        self,
        upstream: str,
        certfile: str,
        keyfile: str,
        *,
        host: str = "127.0.0.1",
        port: int = 8443,
        verbose: bool = False,
    ) -> None:
        self.upstream = upstream.rstrip("/")
        self.host = host
        self.port = port
        self.verbose = verbose
        self.stats = FrontStats()

        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        # 允许 TLS 1.2 —— 不少 HTTP 客户端仍默认 1.2，而它们的指纹正是要测的对象
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    # --- 生命周期 ---

    def __enter__(self) -> "TlsFront":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(64)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def _serve(self) -> None:
        assert self._sock is not None
        selector = selectors.DefaultSelector()
        selector.register(self._sock, selectors.EVENT_READ)
        while not self._stop.is_set():
            if not selector.select(timeout=0.3):
                continue
            try:
                client, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    # --- 单个连接 ---

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(15)
            record = self._read_client_hello(client)
            if record is None:
                return

            try:
                hello = parse_client_hello(record)
            except ClientHelloError as exc:
                self._log(f"ClientHello 解析失败: {exc}")
                return

            session = self._handshake(client, record)
            if session is None:
                return

            self._pump(client, session, hello)
        except (OSError, ssl.SSLError) as exc:
            self._log(f"连接异常: {exc}")
        finally:
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _read_client_hello(client: socket.socket) -> bytes | None:
        """读出完整的第一条 TLS 记录。

        TCP 不保证一次 recv 就拿到整条记录，所以要按记录头声明的长度补齐。
        """
        buffer = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                return None
            buffer += chunk
            try:
                total = record_length(buffer)
            except ClientHelloError:
                return None  # 不是 TLS 流量
            if total is not None and len(buffer) >= total:
                return buffer[:total]
            if len(buffer) > 65536:
                return None

    def _handshake(self, client: socket.socket, replay: bytes) -> "_Session | None":
        """把已读走的 ClientHello 喂回 BIO，然后完成握手。

        这是整个组件的核心技巧：ClientHello 已经被我们从 socket 上读走了，
        普通的 wrap_socket 再也拿不到它。改用 MemoryBIO 手动驱动握手，就能
        先解析、再把原始字节原样交还给 TLS 状态机。
        """
        session = _Session(ssl.MemoryBIO(), ssl.MemoryBIO(), None)  # type: ignore[arg-type]
        session.tls = self._ctx.wrap_bio(
            session.incoming, session.outgoing, server_side=True
        )
        session.incoming.write(replay)

        while True:
            try:
                session.tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                session.flush(client)
                chunk = client.recv(4096)
                if not chunk:
                    return None
                session.incoming.write(chunk)
            except ssl.SSLError as exc:
                self._log(f"握手失败: {exc}")
                return None
        session.flush(client)
        return session

    def _pump(self, client: socket.socket, session: "_Session", hello) -> None:
        """读一个明文 HTTP 请求，转发给上游，把响应加密写回。

        只处理一个请求就关连接（Connection: close）。靶场是测量工具，不是
        高性能网关——连接复用会让"每连接一个 JA3"的对应关系变复杂，而那正是
        这里要测的东西。
        """
        request = self._read_plaintext_request(client, session)
        if not request:
            return
        response = self._forward(request, hello)
        session.write(client, response)

    @staticmethod
    def _read_plaintext_request(client: socket.socket, session: "_Session") -> bytes | None:
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            try:
                chunk = session.tls.read(4096)
            except ssl.SSLWantReadError:
                raw = client.recv(4096)
                if not raw:
                    return None
                session.incoming.write(raw)
                continue
            if not chunk:
                return None
            buffer += chunk
            if len(buffer) > 65536:
                return None
        return buffer

    def _forward(self, request: bytes, hello) -> bytes:
        match = _REQUEST_LINE.match(request)
        if not match:
            return _simple_response(400, b'{"error":"malformed request"}')
        method, path = match.group(1).decode(), match.group(2).decode()

        headers: dict[str, str] = {}
        head, _, _ = request.partition(b"\r\n\r\n")
        for line in head.split(b"\r\n")[1:]:
            key, _, value = line.partition(b":")
            name = key.decode(errors="replace").strip().lower()
            if not name or name in _HOP_BY_HOP or name in _OVERRIDDEN:
                continue
            headers[name] = value.decode(errors="replace").strip()

        user_agent = headers.get("user-agent", "")
        self.stats.note(hello.ja3, hello.ja3_string, user_agent)

        # 强制覆盖：客户端自报的一律作废，指纹只能由本代理说了算
        headers["x-bw-ja3"] = hello.ja3
        headers["x-bw-ja3-string"] = hello.ja3_string
        if hello.server_name:
            headers["x-bw-tls-sni"] = hello.server_name
        headers.pop("host", None)

        self._log(f"{method} {path}  ja3={hello.ja3}  ua={user_agent[:40]!r}")

        req = urllib.request.Request(f"{self.upstream}{path}", headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return _simple_response(resp.status, resp.read(), dict(resp.headers))
        except urllib.error.HTTPError as exc:
            return _simple_response(exc.code, exc.read(), dict(exc.headers))
        except urllib.error.URLError as exc:
            return _simple_response(502, f'{{"error":"upstream: {exc}"}}'.encode())

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[tlsfront] {message}", flush=True)


@dataclass
class _Session:
    """一条 TLS 连接：SSLObject 加上它绑定的两个 MemoryBIO。

    SSLObject 本身不公开它绑定的 BIO，而每次读写都要手动搬运字节，所以把
    三者绑在一起传，比用全局表按 id 反查干净得多。
    """

    incoming: ssl.MemoryBIO
    outgoing: ssl.MemoryBIO
    tls: ssl.SSLObject

    def flush(self, client: socket.socket) -> None:
        pending = self.outgoing.read()
        if pending:
            client.sendall(pending)

    def write(self, client: socket.socket, payload: bytes) -> None:
        self.tls.write(payload)
        self.flush(client)
        try:
            self.tls.unwrap()  # 发 close_notify，让客户端知道响应完整
        except (ssl.SSLError, OSError):
            pass
        try:
            self.flush(client)
        except OSError:
            pass


def _simple_response(status: int, body: bytes, headers: dict[str, str] | None = None) -> bytes:
    reason = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 502: "Bad Gateway"}
    lines = [f"HTTP/1.1 {status} {reason.get(status, 'Status')}"]
    for key, value in (headers or {}).items():
        if key.lower() in _HOP_BY_HOP | {"content-length", "transfer-encoding"}:
            continue
        lines.append(f"{key}: {value}")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body
