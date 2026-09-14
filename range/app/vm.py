"""随机化虚拟机挑战 —— 真正逼出 JS 运行时的机制。

为什么需要它
------------
靶场原来的 L4 只做一件事：检查客户端提交的环境快照**自洽不自洽**。这是
"校验声明"，不是"要求证明"——攻击方手写一份互相不矛盾的 JSON 就能过
（harness 里的 enveloped.py 正是这么干的）。L2、L5 有同样的毛病。

真实防御的分水岭在这里：**从"验证你声称的"变成"要求你执行我现场给的东西"**。
瑞数五代、acw_sc__v2、a_bogus 背后的核心都是这个——下发一段每次都不同的
混淆代码，你必须真的跑它。

机制
----
1. 服务端按 `session` 确定性地生成一段**栈式虚拟机字节码**
2. 服务端把字节码 + 一个解释它的 JS 一起下发；strict 档起**操作码编号逐会话打乱**
3. 客户端在真实 JS 运行时里执行，得到一个 32 位 token
4. 服务端用同一份程序在 Python 里重算，比对

程序由 session 确定性派生，所以服务端**不需要存任何状态**就能复算。

这个设计对应了真实世界的攻防阶梯
--------------------------------
  lenient   操作码表固定         -> 攻击方写一次 VM 模拟器就能一劳永逸（现实中被攻破的状态）
  strict    操作码表逐会话打乱    -> 模拟器每次失效，必须从 JS 里动态提取表，或者干脆跑 JS 引擎
  paranoid  更长的程序 + 环境校验 -> 光有 JS 引擎不够，还要环境自洽

输入含 ts 与 nonce，因此**每个请求都要跑一次 VM**。这让防御对攻击方产生
可度量的 CPU 成本——harness 会把它测出来。
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

MASK = 0xFFFFFFFF

# --- 操作码。名字是稳定的，数值可能被逐会话打乱。---
OPS: tuple[str, ...] = (
    "PUSH",  # 压入立即数
    "LOAD",  # 压入 input[arg]
    "DUP",
    "SWAP",
    "DROP",
    "ADD",
    "SUB",
    "MUL",
    "XOR",
    "AND",
    "OR",
    "SHL",  # 左移 arg 位
    "SHR",  # 逻辑右移 arg 位
    "ROTL",  # 循环左移 arg 位
    "NOT",
    "MIX",  # murmur3 finalizer
)

#: 栈深度变化：(最少需要的深度, 执行后的深度增量)
_ARITY: dict[str, tuple[int, int]] = {
    "PUSH": (0, +1),
    "LOAD": (0, +1),
    "DUP": (1, +1),
    "SWAP": (2, 0),
    "DROP": (1, -1),
    "ADD": (2, -1),
    "SUB": (2, -1),
    "MUL": (2, -1),
    "XOR": (2, -1),
    "AND": (2, -1),
    "OR": (2, -1),
    "SHL": (1, 0),
    "SHR": (1, 0),
    "ROTL": (1, 0),
    "NOT": (1, 0),
    "MIX": (1, 0),
}

INPUT_COUNT = 3
MAX_DEPTH = 8


class _Rng:
    """基于 sha256 的确定性伪随机流。

    不用 random.Random：那是 Python 实现细节，跨版本不保证一致，而靶场的
    可复现性要求同一个 seed 在任何机器、任何版本上生成同一段程序。
    """

    def __init__(self, seed: str) -> None:
        self._seed = seed.encode()
        self._counter = 0
        self._buf = b""

    def _refill(self) -> None:
        self._buf += hashlib.sha256(self._seed + self._counter.to_bytes(8, "big")).digest()
        self._counter += 1

    def u32(self) -> int:
        while len(self._buf) < 4:
            self._refill()
        value = int.from_bytes(self._buf[:4], "big")
        self._buf = self._buf[4:]
        return value

    def below(self, n: int) -> int:
        return self.u32() % n

    def choice(self, seq):
        return seq[self.below(len(seq))]

    def shuffled(self, seq) -> list:
        """Fisher-Yates。用自己的流，保证跨语言可复现。"""
        items = list(seq)
        for i in range(len(items) - 1, 0, -1):
            j = self.below(i + 1)
            items[i], items[j] = items[j], items[i]
        return items


def fnv1a(text: str) -> int:
    """32 位 FNV-1a。两端都要算，选它是因为实现短到不可能写错。"""
    h = 0x811C9DC5
    for byte in text.encode():
        h = ((h ^ byte) * 0x01000193) & MASK
    return h


def mix32(x: int) -> int:
    """murmur3 finalizer。雪崩效应好，且 JS 侧用 Math.imul 能逐位对齐。"""
    x &= MASK
    x ^= x >> 16
    x = (x * 0x85EBCA6B) & MASK
    x ^= x >> 13
    x = (x * 0xC2B2AE35) & MASK
    x ^= x >> 16
    return x


@dataclass(frozen=True)
class Challenge:
    """一次 VM 挑战。完全由 seed 派生，服务端无需存储。"""

    seed: str
    program: tuple[tuple[str, int], ...]
    #: 操作码名 -> 本会话使用的数值
    opcode_map: dict[str, int]

    @property
    def length(self) -> int:
        return len(self.program)


#: 用于检验"输出是否依赖每个输入"的探针向量。
_PROBE_INPUTS: tuple[list[int], ...] = (
    [1, 2, 3],
    [0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35],
    [0, 0, 0],
)


def build_challenge(seed: str, *, length: int = 64, shuffle_opcodes: bool = False) -> Challenge:
    """生成一次挑战，并保证输出真的依赖全部输入。

    为什么要验证依赖性：程序里可能 LOAD 了某个输入随后又 DROP 掉，于是输出
    与它无关。若输出不依赖 ts/nonce，token 就退化成**每会话一个常量**——
    攻击方跑一次 VM 就能跨请求重放，"每个请求都要执行"这个性质荡然无存。

    验证不过就换一个确定性的种子后缀重来。重试计数本身是确定的，所以整个
    过程仍然可复现。
    """
    for attempt in range(16):
        salted = seed if attempt == 0 else f"{seed}#{attempt}"
        rng = _Rng(salted)
        opcode_map = _make_opcode_map(rng, shuffle_opcodes)
        program = _generate_program(rng, length)
        if _depends_on_all_inputs(program):
            return Challenge(seed=seed, program=program, opcode_map=opcode_map)
    raise RuntimeError(f"无法为 seed={seed!r} 生成依赖全部输入的程序")


def _depends_on_all_inputs(program: tuple[tuple[str, int], ...]) -> bool:
    """每个输入都必须能单独改变输出。

    只要存在一组探针输入，扰动 input[i] 会让输出变化，就认定输出依赖它。
    """
    for index in range(INPUT_COUNT):
        if not any(
            _execute_program(program, _perturb(base, index)) != _execute_program(program, base)
            for base in _PROBE_INPUTS
        ):
            return False
    return True


def _perturb(inputs: list[int], index: int) -> list[int]:
    changed = list(inputs)
    changed[index] = (changed[index] + 0x9E3779B9) & MASK
    return changed


def _make_opcode_map(rng: _Rng, shuffle: bool) -> dict[str, int]:
    if not shuffle:
        return {name: index for index, name in enumerate(OPS)}
    # 打乱到 0..255，让编号既不连续也不可预测。攻击方写死的 VM 模拟器
    # 会在每个新会话上失效——这正是 strict 档要制造的困难。
    values = rng.shuffled(range(256))[: len(OPS)]
    return dict(zip(OPS, values))


#: 收尾段每个输入占的指令数：LOAD / PUSH / MUL / ROTL / XOR
_TAIL_PER_INPUT = 5


def _generate_program(rng: _Rng, length: int) -> tuple[tuple[str, int], ...]:
    """生成一段栈永不下溢、最终归约到单值、且输出依赖全部输入的程序。

    分两段：

    **主体** 自由随机。这里允许 AND / OR / SHR / 乘偶数这些**销毁信息位**的
    操作——真实的混淆代码就长这样，也让静态分析更难。

    **收尾** 把每个输入各经一个 32 位双射（乘奇数再循环移位）折进累加器。
    乘奇数在模 2^32 下是双射，循环移位也是，所以每个输入的信息一定被保留。

    收尾段是必需的，不是锦上添花：纯自由随机的主体有 80% 以上的概率把某个
    输入的影响彻底抹掉，那样 token 就退化成每会话一个常量，攻击方跑一次 VM
    就能跨请求重放——"每个请求都要执行"这个性质直接失效。
    """
    program: list[tuple[str, int]] = []
    depth = 0

    # 先把输入压进栈，主体才会真的用到 ts/nonce
    for index in range(INPUT_COUNT):
        program.append(("LOAD", index))
        depth += 1

    body_target = max(len(program), length - INPUT_COUNT * _TAIL_PER_INPUT - 1)
    while len(program) < body_target:
        candidates = [
            name
            for name in OPS
            # 下界 1 而不是 0：栈永远不许被清空，否则后面的一元操作会对空栈执行
            if _ARITY[name][0] <= depth and 1 <= depth + _ARITY[name][1] <= MAX_DEPTH
        ]
        name = rng.choice(candidates)
        program.append((name, _argument_for(name, rng)))
        depth += _ARITY[name][1]

    # 归约到单值：栈上还剩几个就异或几次
    while depth > 1:
        program.append(("XOR", 0))
        depth -= 1

    # 收尾：acc ^= rotl(input[i] * odd_i, k_i)，每一步都是双射
    for index in range(INPUT_COUNT):
        program.append(("LOAD", index))
        program.append(("PUSH", rng.u32() | 1))  # 奇数 -> 模 2^32 下可逆
        program.append(("MUL", 0))
        program.append(("ROTL", 1 + rng.below(31)))
        program.append(("XOR", 0))

    program.append(("MIX", 0))
    return tuple(program)


def _argument_for(name: str, rng: _Rng) -> int:
    if name == "PUSH":
        return rng.u32()
    if name == "LOAD":
        return rng.below(INPUT_COUNT)
    if name in ("SHL", "SHR", "ROTL"):
        return 1 + rng.below(31)  # 0 位移是空操作，31 位内才有意义
    return 0


# --- 执行（服务端侧的权威实现）---


def execute(challenge: Challenge, inputs: list[int]) -> int:
    return _execute_program(challenge.program, inputs)


def _execute_program(program: tuple[tuple[str, int], ...], inputs: list[int]) -> int:
    stack: list[int] = []
    for name, arg in program:
        if name == "PUSH":
            stack.append(arg & MASK)
        elif name == "LOAD":
            stack.append(inputs[arg] & MASK)
        elif name == "DUP":
            stack.append(stack[-1])
        elif name == "SWAP":
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif name == "DROP":
            stack.pop()
        elif name == "NOT":
            stack[-1] = (~stack[-1]) & MASK
        elif name == "MIX":
            stack[-1] = mix32(stack[-1])
        elif name == "SHL":
            stack[-1] = (stack[-1] << arg) & MASK
        elif name == "SHR":
            stack[-1] = (stack[-1] & MASK) >> arg
        elif name == "ROTL":
            value = stack[-1] & MASK
            stack[-1] = ((value << arg) | (value >> (32 - arg))) & MASK
        else:  # 二元运算
            b = stack.pop()
            a = stack.pop()
            if name == "ADD":
                stack.append((a + b) & MASK)
            elif name == "SUB":
                stack.append((a - b) & MASK)
            elif name == "MUL":
                stack.append((a * b) & MASK)
            elif name == "XOR":
                stack.append((a ^ b) & MASK)
            elif name == "AND":
                stack.append(a & b)
            elif name == "OR":
                stack.append(a | b)
            else:
                raise ValueError(f"未知操作码: {name}")
    return stack[-1] & MASK


def make_inputs(seed32: int, ts_ms: int, nonce: str) -> list[int]:
    """VM 的三个输入。含 ts 与 nonce，所以每个请求都要重跑一次。"""
    return [seed32 & MASK, ts_ms & MASK, fnv1a(nonce)]


def seed32_of(seed: str) -> int:
    return int.from_bytes(hashlib.sha256(seed.encode()).digest()[:4], "big")


# --- 下发给客户端的 JS ---


def encode_program(challenge: Challenge) -> str:
    """字节码序列化：每条指令 5 字节（1 字节操作码 + 4 字节大端参数）。"""
    out = bytearray()
    for name, arg in challenge.program:
        out.append(challenge.opcode_map[name])
        out += (arg & MASK).to_bytes(4, "big")
    return base64.b64encode(bytes(out)).decode()


#: 操作码名 -> JS 语句。分支顺序在发出时按本会话的数值排列。
_JS_BODY: dict[str, str] = {
    "PUSH": "S.push(a);",
    "LOAD": "S.push(I[a]>>>0);",
    "DUP": "S.push(S[S.length-1]);",
    "SWAP": "t=S[S.length-1];S[S.length-1]=S[S.length-2];S[S.length-2]=t;",
    "DROP": "S.pop();",
    "NOT": "S[S.length-1]=(~S[S.length-1])>>>0;",
    "MIX": "x=S[S.length-1];x^=x>>>16;x=Math.imul(x,0x85ebca6b);x^=x>>>13;"
           "x=Math.imul(x,0xc2b2ae35);x^=x>>>16;S[S.length-1]=x>>>0;",
    "SHL": "S[S.length-1]=(S[S.length-1]<<a)>>>0;",
    "SHR": "S[S.length-1]=S[S.length-1]>>>a;",
    "ROTL": "x=S[S.length-1];S[S.length-1]=((x<<a)|(x>>>(32-a)))>>>0;",
    "ADD": "b=S.pop();S[S.length-1]=(S[S.length-1]+b)>>>0;",
    "SUB": "b=S.pop();S[S.length-1]=(S[S.length-1]-b)>>>0;",
    # 必须用 Math.imul：普通乘法超过 2^53 就丢精度，与服务端对不上
    "MUL": "b=S.pop();S[S.length-1]=Math.imul(S[S.length-1],b)>>>0;",
    "XOR": "b=S.pop();S[S.length-1]=(S[S.length-1]^b)>>>0;",
    "AND": "b=S.pop();S[S.length-1]=(S[S.length-1]&b)>>>0;",
    "OR": "b=S.pop();S[S.length-1]=(S[S.length-1]|b)>>>0;",
}


def emit_js(challenge: Challenge) -> str:
    """生成解释本次字节码的 JS 函数体。

    签名约定：`new Function("I", body)`，I 是输入数组，返回 32 位无符号整数。

    这段 JS 每会话都不同——不是因为加了混淆，而是因为**程序本身和操作码
    编号都变了**。随机化才是防御，混淆只是附赠。
    """
    cases = "".join(
        f"case {challenge.opcode_map[name]}:{_JS_BODY[name]}break;"
        for name in sorted(OPS, key=lambda n: challenge.opcode_map[n])
    )
    return (
        f'var P="{encode_program(challenge)}";'
        "var B=atob(P),S=[],t,x,b,a,o;"
        "for(var i=0;i<B.length;i+=5){"
        "o=B.charCodeAt(i);"
        "a=((B.charCodeAt(i+1)<<24)|(B.charCodeAt(i+2)<<16)"
        "|(B.charCodeAt(i+3)<<8)|B.charCodeAt(i+4))>>>0;"
        f"switch(o){{{cases}}}"
        "}"
        "return S[S.length-1]>>>0;"
    )


def token_hex(value: int) -> str:
    return f"{value & MASK:08x}"
