"""JA3 解析的测试。

最要紧的一条是 GREASE 剔除：浏览器每次连接都会往密码套件、扩展、椭圆曲线里
随机插保留值。不剔除的话，同一个浏览器每次算出的 JA3 都不同，整个指纹机制
直接作废——而且症状是"偶尔拦错人"，极难排查。
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from tlsfront import ja3


def build_client_hello(
    *,
    legacy_version: int = 0x0303,
    ciphers: list[int] | None = None,
    extensions: list[tuple[int, bytes]] | None = None,
    session_id: bytes = b"",
) -> bytes:
    """手工拼一个 ClientHello。

    自己拼而不是抓真包，是因为测试要能精确控制 GREASE 的位置和边界条件。
    真实客户端的验证由 test_tlsfront.py 的集成测试负责。
    """
    ciphers = ciphers if ciphers is not None else [0x1301, 0x1302]
    extensions = extensions if extensions is not None else []

    body = struct.pack(">H", legacy_version)
    body += b"\x00" * 32  # random
    body += bytes([len(session_id)]) + session_id
    body += struct.pack(">H", len(ciphers) * 2) + b"".join(struct.pack(">H", c) for c in ciphers)
    body += b"\x01\x00"  # compression_methods: [null]

    ext_blob = b"".join(
        struct.pack(">HH", ext_type, len(payload)) + payload for ext_type, payload in extensions
    )
    body += struct.pack(">H", len(ext_blob)) + ext_blob

    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def supported_groups(curves: list[int]) -> tuple[int, bytes]:
    payload = struct.pack(">H", len(curves) * 2) + b"".join(struct.pack(">H", c) for c in curves)
    return (0x000A, payload)


def ec_point_formats(formats: list[int]) -> tuple[int, bytes]:
    return (0x000B, bytes([len(formats)]) + bytes(formats))


# --- GREASE ---


def test_grease_values_recognised():
    for high in range(0x0A, 0x100, 0x10):
        assert ja3.is_grease((high << 8) | high), f"0x{high:02x}{high:02x} 应被识别为 GREASE"
    assert len([v for v in range(0x10000) if ja3.is_grease(v)]) == 16


def test_real_values_not_mistaken_for_grease():
    for value in (0x1301, 0x1302, 0x1303, 0xC02B, 0x0017, 0x001D, 0x0000, 0xFFFF, 0x0A0B, 0x1A0A):
        assert not ja3.is_grease(value), f"0x{value:04x} 被误判为 GREASE"


def test_grease_stripped_from_ciphers():
    """带 GREASE 与不带 GREASE 的 ClientHello 必须算出同一个 JA3。"""
    plain = build_client_hello(ciphers=[0x1301, 0x1302, 0x1303])
    greased = build_client_hello(ciphers=[0x0A0A, 0x1301, 0x1302, 0xFAFA, 0x1303])
    assert ja3.ja3_of(greased) == ja3.ja3_of(plain)


def test_grease_stripped_from_extensions():
    plain = build_client_hello(extensions=[supported_groups([0x001D]), ec_point_formats([0])])
    greased = build_client_hello(
        extensions=[(0x2A2A, b""), supported_groups([0x001D]), (0xBABA, b""), ec_point_formats([0])]
    )
    assert ja3.ja3_of(greased) == ja3.ja3_of(plain)


def test_grease_stripped_from_curves():
    plain = build_client_hello(extensions=[supported_groups([0x001D, 0x0017])])
    greased = build_client_hello(extensions=[supported_groups([0x3A3A, 0x001D, 0x0017])])
    assert ja3.ja3_of(greased) == ja3.ja3_of(plain)


def test_rotating_grease_gives_stable_fingerprint():
    """模拟浏览器每次换 GREASE 值：指纹必须纹丝不动。

    这是 GREASE 剔除真正要防的事故——否则症状是"同一个浏览器偶尔被拦"。
    """
    fingerprints = set()
    for grease in (0x0A0A, 0x1A1A, 0x8A8A, 0xFAFA):
        hello = build_client_hello(
            ciphers=[grease, 0x1301, 0x1302],
            extensions=[(grease, b""), supported_groups([grease, 0x001D])],
        )
        fingerprints.add(ja3.ja3_of(hello))
    assert len(fingerprints) == 1, f"GREASE 轮换导致指纹漂移: {fingerprints}"


# --- JA3 字符串构成 ---


def test_ja3_string_layout():
    hello = build_client_hello(
        legacy_version=0x0303,
        ciphers=[0x1301, 0x1302],
        extensions=[supported_groups([0x001D, 0x0017]), ec_point_formats([0])],
    )
    parsed = ja3.parse_client_hello(hello)
    assert parsed.ja3_string == "771,4865-4866,10-11,29-23,0"
    assert parsed.ja3 == hashlib.md5(parsed.ja3_string.encode()).hexdigest()


def test_uses_legacy_version_not_record_version():
    """JA3 取 body 里的 legacy_version。TLS 1.3 客户端在这里一律写 0x0303。"""
    hello = build_client_hello(legacy_version=0x0303)
    assert ja3.parse_client_hello(hello).ja3_string.startswith("771,")


def test_cipher_order_matters():
    """顺序是指纹的一部分——同一组套件换个顺序就是不同的客户端。"""
    a = ja3.ja3_of(build_client_hello(ciphers=[0x1301, 0x1302]))
    b = ja3.ja3_of(build_client_hello(ciphers=[0x1302, 0x1301]))
    assert a != b


def test_extension_order_matters():
    a = ja3.ja3_of(build_client_hello(extensions=[supported_groups([0x001D]), ec_point_formats([0])]))
    b = ja3.ja3_of(build_client_hello(extensions=[ec_point_formats([0]), supported_groups([0x001D])]))
    assert a != b


def test_missing_optional_extensions_give_empty_fields():
    parsed = ja3.parse_client_hello(build_client_hello(extensions=[]))
    assert parsed.ja3_string.endswith(",,")  # curves 与 point_formats 均为空


def test_session_id_does_not_affect_fingerprint():
    """会话 id 每次都不同，绝不能进指纹。"""
    a = ja3.ja3_of(build_client_hello(session_id=b"\x01" * 32))
    b = ja3.ja3_of(build_client_hello(session_id=b"\x02" * 32))
    assert a == b


# --- SNI ---


def test_sni_extracted():
    host = b"range.local"
    payload = struct.pack(">H", len(host) + 3) + b"\x00" + struct.pack(">H", len(host)) + host
    parsed = ja3.parse_client_hello(build_client_hello(extensions=[(0x0000, payload)]))
    assert parsed.server_name == "range.local"


def test_sni_absent_is_none():
    assert ja3.parse_client_hello(build_client_hello()).server_name is None


# --- 健壮性：输入来自不可信对端 ---


def test_record_length_needs_header():
    assert ja3.record_length(b"\x16\x03") is None


def test_record_length_reads_declared_size():
    assert ja3.record_length(b"\x16\x03\x01\x00\x40" + b"x" * 10) == 5 + 0x40


def test_non_handshake_record_rejected():
    with pytest.raises(ja3.ClientHelloError):
        ja3.record_length(b"\x17\x03\x01\x00\x10")


def test_truncated_record_rejected():
    full = build_client_hello()
    with pytest.raises(ja3.ClientHelloError):
        ja3.parse_client_hello(full[: len(full) // 2])


def test_oversized_length_field_rejected():
    """长度字段声称的比实到的多 —— 最典型的恶意输入。"""
    hello = bytearray(build_client_hello())
    hello[3:5] = struct.pack(">H", 0xFFFF)
    with pytest.raises(ja3.ClientHelloError):
        ja3.parse_client_hello(bytes(hello))


def test_odd_cipher_list_length_rejected():
    hello = bytearray(build_client_hello(ciphers=[0x1301]))
    # 密码套件列表长度改成奇数，2 字节项的列表不可能是奇数长
    index = hello.index(struct.pack(">H", 2), 5 + 4 + 2 + 32 + 1)
    hello[index : index + 2] = struct.pack(">H", 3)
    with pytest.raises(ja3.ClientHelloError):
        ja3.parse_client_hello(bytes(hello))


def test_empty_input_rejected():
    with pytest.raises(ja3.ClientHelloError):
        ja3.parse_client_hello(b"")


def test_garbage_rejected_not_crashed():
    for payload in (b"\x16", b"\x16\x03\x01\x00\x00", b"GET / HTTP/1.1\r\n\r\n"):
        with pytest.raises(ja3.ClientHelloError):
            ja3.parse_client_hello(payload)
