# CostLadder

**采集成本模型，不是验证码基准。**

给定一个站点的防御特征，你该停在成本阶梯的哪一级、为什么、每万条数据要花多少钱。

---

## 这个项目在回答什么问题

现有的验证码基准（[Open CaptchaWorld](https://github.com/MetaAgentX/OpenCaptchaWorld)、[Halligan](https://www.usenix.org/conference/usenixsecurity25/presentation/teoh)、MCA-Bench、CAPTCHA-X）回答的是「**某个模型在这批图上准确率多少**」。分析单元是模型，指标是准确率。

采集方要回答的是另一个问题：「**这个站的数据每万条采下来要花多少钱，最便宜的路径是哪条**」。分析单元是防御配置，指标是单位成本。准确率 40% 但单次成本 $0.02 的方案，和准确率 95% 但单次成本 $0.0005 的方案，在工程决策里完全不是一回事——而准确率指标看不出这个差别。

三个支撑论点，展开见 [`docs/01-thesis.md`](docs/01-thesis.md)：

> **验证码是失败模式，不是关卡。** 你看到验证码，说明你在前面某一层已经露馅了。资深做法是回头查是哪一层漏的，而不是去解那道题。

> **采集工程的核心手艺，是「能不能不用浏览器」。** 无头浏览器相对纯 HTTP 的成本差是一到两个数量级，这一跳发生在协议层：签名能不能脱离浏览器静态复现。

> **入口选择先于技术选择。** 硬闯一层防御的成本，经常是换一个入口（移动端 API、小程序、开放平台）的几十倍。

---

## 成本阶梯

| 级别 | 方案 | 相对成本 | 被迫停在这里的原因 |
|---|---|---|---|
| **L0** | 纯 HTTP + 数据中心 IP | 1× | — |
| **L1** | HTTP + 复现签名 | ~1× 边际 + 一次性逆向工时 | L3 协议层 |
| **L2** | HTTP + 住宅/移动 IP | ~10× | L1 网络层 |
| **L3** | 轻量 JS 引擎 | ~15× | L3 协议层 `runtime` 档 |
| **L4** | 完整无头浏览器 + 指纹伪装 | ~50× | L4 运行时层 |
| **L5** | 真浏览器 + 可信交互 | ~200× | L5 行为层 |

**相对成本是待测量的对象，不是预设结论。** 上表数字是立项时的先验估计，靶场存在的意义就是把它们替换成实测值。

一个常见且昂贵的误判：在 L2 被拦，以为"要上浏览器"直接跳到阶梯 L4，白白付出约 50 倍成本——而正确应对只是换一个具备 TLS 指纹伪装能力的 HTTP 客户端，成本增量几乎为零。这正是靶场归因能力的直接价值。

---

## 靶场

把真实站点上叠加的防御拆成六个可独立开关的层，每层单独启用、单独调强度。拆开的目的只有一个：**让「我被拦了」变成「我被第 N 层拦了，因为 X」**。

| 层 | 检验对象 | 被它拦住意味着 |
|---|---|---|
| L1 网络 | IP 段类型、频率、会话并发 | 代理档位不够 |
| L2 传输 | JA3/JA4、HTTP2 指纹、与 UA 的交叉一致性 | HTTP 客户端选型不对 |
| **L3 协议** | **请求签名、时效、重放** | **还没复现签名 ← 成本差最大的分水岭** |
| L4 运行时 | JS 环境属性的自洽性 | 需要真实浏览器运行时 |
| L5 行为 | 事件间隔分布、路径曲率、速度连续性 | 需要真浏览器 + 可信交互 |
| L6 验证码 | 一道题（默认关闭，仅在前五层累计风险分超阈值时触发） | 前面已经露馅了 |

完整规格见 [`docs/02-defense-layers.md`](docs/02-defense-layers.md)。

### 两种响应模式

| 模式 | 被拦时 | 用途 |
|---|---|---|
| `diagnostic` | 403 + 明确告知被哪层拦、原因码、细节 | 开发、教学、回归测试 |
| `blind` | 200 + **结构合法但内容虚假的数据** | 测量没有归因帮助时的排障工时 |

`blind` 不是装饰。它测量采集工程里最贵、也最少被量化的一项成本：管线昨天好好的今天全挂，定位原因的工时。这项在所有现有评测里都不被计入。

---

## 快速开始

```bash
python3 -m venv .venv && .venv/bin/pip install -e range -e harness pytest
.venv/bin/python -m pytest range/tests harness/tests    # 71 passed
```

### 一、看成本决策表

```console
$ .venv/bin/costladder scan -p cdn-standard -p api-signed -n 100

══ cdn-standard [diagnostic/gate] ══
攻击实现      级    真值   请求      R     实测/万条   摊销/万条   合计/万条   主要拦截原因
naive        L0      0     15      ∞           ∞       0.02         ∞    ja3_absent
spoofed      L0    100      5   1.00×   1.25e-04       0.08      0.08    —
signed       L1    100      6   1.00×   1.29e-04       0.96      0.96    —
traced       L5    100      6   1.00×   1.80e-04       2.24      2.24    —

  → 最优：spoofed（阶梯 L0），合计 0.08 / 万条
     误判成本：错选 traced（L5）要多付 28.0 倍
```

最后一行就是这个项目要防的那个误判，被量化了：在 L2 被拦时换个客户端库就够，误以为"要上浏览器"要多付 28 倍。`legacy-gov` 上这个倍数是 139。

**实测列由 harness 强制计量，攻击实现无法影响；摊销列来自申报工时，harness 无法核实。两者永远分列，不混合。** 详见 [`harness/README.md`](harness/README.md)。

### 二、看靶场的归因输出

```bash
CL_PROFILE=hardened .venv/bin/uvicorn app.main:app --port 8900 --app-dir range
```

另开终端，看一个什么都不做的采集器会得到什么：

```console
$ cd range && ../.venv/bin/python -m tools.refclient --port 8900 --naive
GET /api/items -> HTTP 403
  被 l2_transport 拦住：ja3_absent      -> 换个客户端即可，不必升级架构（成本增量≈0）
  被 l3_protocol 拦住：sign_missing     -> 需要爬到成本阶梯 L3
  被 l4_runtime  拦住：env_missing      -> 需要爬到成本阶梯 L4
  被 l5_behavior 拦住：trace_missing    -> 需要爬到成本阶梯 L5
  被 l6_captcha  拦住：captcha_required -> 需要爬到成本阶梯 L5
```

### 三、看 blind 模式怎么静默投毒

```console
$ .venv/bin/costladder scan -p api-signed -a naive --mode blind -n 100
naive       L0        0      5      ∞           ∞       0.02         ∞    —
              ⚠ 收到 100 条投毒数据（HTTP 200 但内容是假的）
```

HTTP 全 200、没有任何失败信号、归因栏是空的，而真值 0 条。**只统计状态码的采集器会悄无声息地采走垃圾**，并因此高估通过率、低估单位成本。

### 内置 profile

| Profile | 组合 | 对应现实 |
|---|---|---|
| `open` | 全关 | 基线，测量纯采集成本本身 |
| `legacy-gov` | L1 宽松 + L6 | 政企/传统行业后台 |
| `cdn-standard` | L1 + L2 | 挂了标准 CDN 防护的普通站点 |
| `api-signed` | L1 + L2 + L3 | 国内主流内容平台 Web 端 |
| `hardened` | 六层全开，评分形态 | 高价值目标 |

Profile 是实验的自变量，成本是因变量。所有结果必须标注 `name@version` 与价格表版本，否则不可比。

---

## 项目边界

**只在自己的靶场上测量成本，不针对任何第三方线上服务。** 完整说明见 [`docs/04-scope.md`](docs/04-scope.md)。

- 不复现任何具体商业站点的签名算法或防御实现——靶场里的签名方案是自造的，只在结构上与真实方案同构
- 不把第三方线上站点作为测量目标——不可复现、不可归因、无授权
- 不提供针对线上服务的求解器或绕过工具
- 不收集任何真实个人数据——被采集的数据全部为程序生成的合成数据

这不是在能力和合规之间做取舍。靶场化**同时**提高了技术价值和可用性：真站会改版（数据一周就过期）、多层叠加测不出单层贡献，而单层贡献恰恰是"该换库还是该换架构"这个判断的全部依据。

---

## 当前状态

v0.1，靶场与 harness 均可用，已能跑出第一组成本数据。

**已完成**
- **靶场**：六层防御，可独立开关、分 `lenient`/`strict`/`paranoid` 三档；`gate`/`score` 两种判定形态，`diagnostic`/`blind` 两种响应模式；5 个内置 profile
- **harness**：强制计量的反向代理（攻击实现拿不到靶场真实地址，无法绕过计量）、成本模型、阶梯扫描、决策表输出
- 6 个攻击实现构成完整阶梯（L0 → L5），含一个真浏览器实现（Playwright 跑站点自己的 JS）
- **交叉点分析**：`browser` 与 `signed` 是两条相反的经济路径（边际成本 vs 一次性逆向工时）。`browser` 加载整页约 800 KB 资产，边际成本实测是 `signed` 的约 48 倍。模型给出"采集量大到多少才值得逆向"的量化答案，且强烈依赖代理档位——datacenter 档约 8.5 亿条/年，residential 档约 1500 万条/年（代理越贵，逆向越早回本）
- 81 项测试，含 7 项端到端

**未完成**
- **引入真实代理延迟与失败率**。整页流量已建模（`browser` 加载约 800 KB 资产，边际成本实测约为 `signed` 的 48 倍），但页面权重是可调估计值、且未含代理延迟——这是交叉点数字的主要不确定来源
- `tlsfront`：解析 ClientHello 计算 JA3 的前置代理。在它就位前 L2 依赖客户端自报 `X-CL-JA3`，**L2 的测量数据不具备对外可比性**
- 真实指纹集录制。`fingerprints/demo.yaml` 全是占位符，不是真实 JA3
- 容器化 + cgroup 计量（当前用 `getrusage`，能透传捕获 chromium 的 CPU，但隔离不彻底，且只支持 Python 攻击实现）
- LLM token 计量，用于接入 VLM 类攻击实现
- `sign.js` 的混淆构建。当前可读，因此 `derived` 档的逆向难度被显著低估
- L6 的 `static_image` 题型（需要图像渲染依赖）

**已知限制**
- 靶场状态存在进程内存，多 worker 部署会让频率统计和 nonce 重放表失效，默认单 worker 运行
- `browser` 过不了 `hardened` 的 paranoid WebGL 校验（headless 软件渲染）——这是有意暴露的边界：运行时层严格档要逼出的是真实 GPU / 真实设备
- `enveloped`/`traced` 的合成手段过得了靶场、过不了真实防御，所以它们的成本是下界
- `dev_hours` 是申报值，harness 核实不了。结论应对它做敏感性分析，而不是依赖单点值

---

## 文档

- [`docs/01-thesis.md`](docs/01-thesis.md) — 为什么是成本不是准确率
- [`docs/02-defense-layers.md`](docs/02-defense-layers.md) — 靶场分层设计规格
- [`docs/03-cost-model.md`](docs/03-cost-model.md) — 单位成本公式与阶梯
- [`docs/04-scope.md`](docs/04-scope.md) — 项目边界
- [`harness/README.md`](harness/README.md) — 强制计量、攻击实现、实测结果与其局限

## License

MIT
