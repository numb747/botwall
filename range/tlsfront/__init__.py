"""tlsfront —— 在握手完成前截下 ClientHello，算出 JA3 注入给靶场。

没有它，L2 只能读客户端自报的 X-BW-JA3 头（开发模式），那一层就是假的。
"""

from .ja3 import ClientHello, ClientHelloError, is_grease, ja3_of, parse_client_hello
from .proxy import TlsFront

__all__ = [
    "ClientHello",
    "ClientHelloError",
    "TlsFront",
    "is_grease",
    "ja3_of",
    "parse_client_hello",
]
