"""随机化 VM 挑战的测试。

最重要的一条是 test_python_and_node_agree —— 服务端用 Python 算期望值，
客户端用 JS 算实际值，两边的 32 位语义必须逐位一致。差一位，整个机制就
变成随机拒绝合法客户端。这条测试真的起一个 Node 进程去跑发出的 JS。
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from app import vm

NODE = shutil.which("node")
requires_node = pytest.mark.skipif(NODE is None, reason="需要 node 才能跑跨语言比对")


def _run_in_node(challenge: vm.Challenge, inputs: list[int]) -> int:
    script = f"""
    globalThis.atob = globalThis.atob || (b => Buffer.from(b,'base64').toString('binary'));
    const f = new Function("I", {json.dumps(vm.emit_js(challenge))});
    console.log(f({json.dumps(inputs)}));
    """
    result = subprocess.run([str(NODE), "-e", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, f"node 执行失败: {result.stderr}"
    return int(result.stdout.strip())


# --- 确定性 ---


def test_same_seed_gives_same_program():
    """靶场可复现性的根基：同一个 seed 在任何机器上生成同一段程序。"""
    a = vm.build_challenge("sess-1", length=64)
    b = vm.build_challenge("sess-1", length=64)
    assert a.program == b.program
    assert a.opcode_map == b.opcode_map


def test_different_seed_gives_different_program():
    a = vm.build_challenge("sess-1", length=64)
    b = vm.build_challenge("sess-2", length=64)
    assert a.program != b.program


def test_shuffled_opcodes_differ_per_session():
    """strict 档的核心：操作码编号逐会话变，写死的 VM 模拟器每次都会失效。"""
    a = vm.build_challenge("sess-1", length=64, shuffle_opcodes=True)
    b = vm.build_challenge("sess-2", length=64, shuffle_opcodes=True)
    assert a.opcode_map != b.opcode_map
    # 编号必须两两不同，否则解释器会把不同指令混为一谈
    assert len(set(a.opcode_map.values())) == len(vm.OPS)


def test_fixed_opcodes_are_stable():
    """lenient 档：编号固定，攻击方写一次模拟器就能一劳永逸。这是有意的。"""
    a = vm.build_challenge("sess-1", length=64, shuffle_opcodes=False)
    b = vm.build_challenge("sess-2", length=64, shuffle_opcodes=False)
    assert a.opcode_map == b.opcode_map


# --- 程序结构 ---


def test_program_never_underflows_and_ends_with_one_value():
    for seed in ("a", "b", "c", "d"):
        challenge = vm.build_challenge(seed, length=120)
        depth = 0
        for name, _ in challenge.program:
            needs, delta = vm._ARITY[name]
            assert depth >= needs, f"{seed}: {name} 在深度 {depth} 处下溢"
            depth += delta
            assert depth <= vm.MAX_DEPTH
        assert depth == 1, f"{seed}: 程序结束时栈深 {depth}，应为 1"


def test_program_reads_every_input():
    """程序必须真的用上 ts 与 nonce，否则结果是常量、可以直接重放。"""
    challenge = vm.build_challenge("x", length=64)
    loaded = {arg for name, arg in challenge.program if name == "LOAD"}
    assert loaded == set(range(vm.INPUT_COUNT))


def test_output_depends_on_every_input():
    challenge = vm.build_challenge("x", length=96)
    base = [1, 2, 3]
    reference = vm.execute(challenge, base)
    for index in range(vm.INPUT_COUNT):
        changed = list(base)
        changed[index] += 1
        assert vm.execute(challenge, changed) != reference, f"输出与 input[{index}] 无关"


def test_result_is_32bit():
    for seed in ("a", "b", "c"):
        challenge = vm.build_challenge(seed, length=80)
        value = vm.execute(challenge, [0xFFFFFFFF, 0xDEADBEEF, 0x12345678])
        assert 0 <= value <= 0xFFFFFFFF


# --- 跨语言一致性（核心）---


@requires_node
@pytest.mark.parametrize("shuffle", [False, True], ids=["fixed_opcodes", "shuffled_opcodes"])
@pytest.mark.parametrize("length", [64, 160])
def test_python_and_node_agree(shuffle: bool, length: int):
    for index in range(4):
        seed = f"cross-{shuffle}-{length}-{index}"
        challenge = vm.build_challenge(seed, length=length, shuffle_opcodes=shuffle)
        inputs = vm.make_inputs(vm.seed32_of(seed), 1789000000000 + index * 977, f"n{index}")
        assert _run_in_node(challenge, inputs) == vm.execute(challenge, inputs)


@requires_node
def test_node_agrees_on_extreme_inputs():
    """32 位边界值最容易暴露两端语义不一致（尤其乘法要用 Math.imul）。"""
    challenge = vm.build_challenge("extreme", length=128, shuffle_opcodes=True)
    for inputs in ([0, 0, 0], [0xFFFFFFFF] * 3, [0x80000000, 1, 0xFFFFFFFF]):
        assert _run_in_node(challenge, inputs) == vm.execute(challenge, inputs)


# --- 辅助函数 ---


def test_fnv1a_matches_known_values():
    # 标准 FNV-1a 32 位测试向量
    assert vm.fnv1a("") == 0x811C9DC5
    assert vm.fnv1a("a") == 0xE40C292C
    assert vm.fnv1a("foobar") == 0xBF9CF968


def test_token_hex_is_eight_chars():
    assert vm.token_hex(0) == "00000000"
    assert vm.token_hex(0xFFFFFFFF) == "ffffffff"
    assert len(vm.token_hex(0x1234)) == 8


def test_emitted_js_does_not_leak_opcode_names():
    """解释器代码里不该出现 PUSH/XOR 这类助记符——那会让静态分析直接还原语义。

    只检查解释器部分，不检查 base64 的程序字面量：base64 字母表里随机撞出
    "OR"、"AND" 这种两三字母的组合是必然的，拿它判定泄漏是假阳性。
    """
    challenge = vm.build_challenge("leak", length=64, shuffle_opcodes=True)
    emitted = vm.emit_js(challenge)
    interpreter = emitted[emitted.index('";') :]  # 跳过 var P="....";
    for name in vm.OPS:
        assert name not in interpreter, f"解释器里泄漏了助记符 {name}"
