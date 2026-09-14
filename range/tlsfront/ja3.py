"""从 ClientHello 原始字节计算 JA3 指纹。

为什么必须在这一层做
--------------------
TLS 指纹由客户端的 **TLS 栈**决定——它提供哪些密码套件、按什么顺序排、带哪些
扩展。这些信息只存在于握手的第一个包里，握手一结束就没了，应用层（FastAPI
的中间件）根本看不到。所以 L2 要想是真的，就必须有一个前置组件在 TCP 字节流
上解析 ClientHello。

这也是为什么 TLS 指纹伪造不了：它不是一个你可以随手加的 header，而是你用的
那个 HTTP 客户端库的固有形状。换库才能换指纹——这正是成本阶梯上 L2 那一跳
"换个客户端即可，成本增量≈0"的由来。

JA3 的定义
----------
    JA3 = TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats

五个字段用逗号连接，字段内的多个值用 `-` 连接，最后取 MD5。

两个容易踩错的点：

**TLSVersion 取的是 ClientHello body 里的 legacy_version，不是记录层的版本，
也不是 supported_versions 扩展里的真实版本。** TLS 1.3 的客户端在这里一律写
0x0303（即 TLS 1.2）以兼容中间设备，真实版本藏在扩展里。JA3 按原始规范取
legacy_version。

**GREASE 值必须剔除**（RFC 8701）。浏览器会在密码套件、扩展、椭圆曲线里随机
插入保留值来防止协议僵化，这些值**每次连接都不同**。不剔除的话同一个浏览器
每次算出的 JA3 都不一样，整个指纹机制就废了。
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

#: 握手记录类型
_RECORD_HANDSHAKE = 0x16
#: 握手消息类型
_HANDSHAKE_CLIENT_HELLO = 0x01

#: 扩展类型
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B


class ClientHelloError(ValueError):
    """ClientHello 解析失败。不是致命错误——非 TLS 流量也会走到这里。"""


def is_grease(value: int) -> bool:
    """RFC 8701 的 GREASE 保留值：两个字节相同，且低半字节为 0xa。

    0x0a0a, 0x1a1a, 0x2a2a, ... 0xfafa 共 16 个。
    """
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


@dataclass(frozen=True)
class ClientHello:
    """从 ClientHello 里抽出的、JA3 需要的那几项。"""

    legacy_version: int
    ciphers: tuple[int, ...]
    extensions: tuple[int, ...]
    curves: tuple[int, ...]
    point_formats: tuple[int, ...]
    server_name: str | None = None

    @property
    def ja3_string(self) -> str:
        return ",".join(
            (
                str(self.legacy_version),
                "-".join(str(c) for c in self.ciphers),
                "-".join(str(e) for e in self.extensions),
                "-".join(str(c) for c in self.curves),
                "-".join(str(p) for p in self.point_formats),
            )
        )

    @property
    def ja3(self) -> str:
        return hashlib.md5(self.ja3_string.encode()).hexdigest()


class _Reader:
    """带边界检查的顺序读取器。

    ClientHello 来自不可信的对端，每一个长度字段都可能是恶意的。统一在这里
    做边界检查，比在十几处散着写 if 要可靠。
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take(self, count: int) -> bytes:
        if count < 0 or self.remaining < count:
            raise ClientHelloError(f"越界读取：要 {count} 字节，只剩 {self.remaining}")
        chunk = self._data[self._pos : self._pos + count]
        self._pos += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u24(self) -> int:
        raw = self.take(3)
        return (raw[0] << 16) | (raw[1] << 8) | raw[2]

    def u16_list(self, byte_length: int) -> tuple[int, ...]:
        if byte_length % 2:
            raise ClientHelloError(f"2 字节项的列表长度不是偶数: {byte_length}")
        raw = self.take(byte_length)
        return struct.unpack(f">{byte_length // 2}H", raw)


def record_length(data: bytes) -> int | None:
    """从 TLS 记录头读出这条记录的总长度（含 5 字节头）。

    数据不足 5 字节时返回 None —— 调用方需要继续读。
    """
    if len(data) < 5:
        return None
    if data[0] != _RECORD_HANDSHAKE:
        raise ClientHelloError(f"不是握手记录，首字节为 0x{data[0]:02x}")
    return 5 + struct.unpack(">H", data[3:5])[0]


def parse_client_hello(record: bytes) -> ClientHello:
    """解析一条完整的 TLS 握手记录，抽出 JA3 所需字段。"""
    reader = _Reader(record)

    if reader.u8() != _RECORD_HANDSHAKE:
        raise ClientHelloError("不是握手记录")
    reader.u16()  # 记录层版本，JA3 不用它
    declared = reader.u16()
    if declared > reader.remaining:
        raise ClientHelloError(f"记录不完整：声称 {declared} 字节，实到 {reader.remaining}")

    if reader.u8() != _HANDSHAKE_CLIENT_HELLO:
        raise ClientHelloError("不是 ClientHello")
    reader.u24()  # 握手消息长度

    # JA3 取的是 body 里的 legacy_version，不是记录层版本
    legacy_version = reader.u16()
    reader.take(32)  # random
    reader.take(reader.u8())  # session_id

    ciphers = tuple(v for v in reader.u16_list(reader.u16()) if not is_grease(v))
    reader.take(reader.u8())  # compression_methods

    extensions: list[int] = []
    curves: tuple[int, ...] = ()
    point_formats: tuple[int, ...] = ()
    server_name: str | None = None

    if reader.remaining >= 2:
        ext_total = reader.u16()
        ext_reader = _Reader(reader.take(min(ext_total, reader.remaining)))
        while ext_reader.remaining >= 4:
            ext_type = ext_reader.u16()
            ext_body = ext_reader.take(ext_reader.u16())
            if is_grease(ext_type):
                continue
            extensions.append(ext_type)
            if ext_type == _EXT_SUPPORTED_GROUPS:
                body = _Reader(ext_body)
                curves = tuple(v for v in body.u16_list(body.u16()) if not is_grease(v))
            elif ext_type == _EXT_EC_POINT_FORMATS:
                body = _Reader(ext_body)
                point_formats = tuple(body.take(body.u8()))
            elif ext_type == 0x0000:  # SNI，不进 JA3，但转发时有用
                server_name = _parse_sni(ext_body)

    return ClientHello(
        legacy_version=legacy_version,
        ciphers=ciphers,
        extensions=tuple(extensions),
        curves=curves,
        point_formats=point_formats,
        server_name=server_name,
    )


def _parse_sni(body: bytes) -> str | None:
    try:
        reader = _Reader(body)
        reader.u16()  # server_name_list 长度
        if reader.u8() != 0:  # name_type: host_name
            return None
        return reader.take(reader.u16()).decode("ascii")
    except (ClientHelloError, UnicodeDecodeError):
        return None


def ja3_of(record: bytes) -> str:
    return parse_client_hello(record).ja3
