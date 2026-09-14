# botwall

**可自托管的反自动化防御靶场。**

六层防御逐层可开关、逐档可调强度；被拦时它会告诉你**是哪一层、为什么**。用于采集工程的练习、教学与回归测试——不必去碰任何人的生产站点。

---

## 为什么需要一个靶场

做采集的人没有地方练手。现有的练习站（`quotes.toscrape.com` 那一类）停留在"把 HTML 解析出来"，不含任何现代防御；而真实站点**不可复现**（随时改版，今天的解法下周失效）、**不可归因**（六层防御叠在一起，不告诉你哪层生效）、**无授权**。

botwall 补的就是这个空白：

- **可复现** — profile 版本钉死，同一个 profile 在任何机器上行为一致；VM 挑战由会话确定性派生，服务端不存状态
- **可归因** — `diagnostic` 模式下明确告诉你被哪层拦、原因码是什么、该怎么应对
- **可授权** — 跑在你自己机器上，不针对任何第三方服务

它同时对防御方有用：想知道自己那套风控值多少钱、误伤多大，可以在这里先量一遍。

---

## 六层防御

拆开的目的只有一个：**让「我被拦了」变成「我被第 N 层拦了，因为 X」**。归因不了，就判断不出该升级哪个环节。

| 层 | 检验对象 | 被它拦住意味着 |
|---|---|---|
| L1 网络 | IP 段类型、频率、会话并发 | 代理档位不够 |
| **L2 传输** | **真实 JA3（tlsfront 解析 ClientHello）、与 UA 的交叉一致性** | **HTTP 客户端选型不对** |
| **L3 协议** | **请求签名、时效、重放** | **还没复现签名 ← 成本差最大的分水岭** |
| **L4 运行时** | **`env`：环境属性自洽性；`vm`：随机化虚拟机挑战** | **需要真实 JS 运行时** |
| **L5 行为** | **`stats`：轨迹统计特征；`task`：几何任务** | **需要真浏览器 + 可信交互** |
| L6 验证码 | `pow` / `slider` / `static_image`（默认关闭，仅在前五层累计风险分超阈值时触发） | 前面已经露馅了 |

完整规格见 [`docs/02-defense-layers.md`](docs/02-defense-layers.md)。

### 靶场里最硬的一档：随机化 VM 挑战

L4 的 `vm` 机制是唯一**纯靠构造 JSON 绝对过不去**的防御。服务端按会话确定性地生成一段**栈式虚拟机字节码**，连同一个解释它的 JS 一起下发，客户端必须真的执行才能算出 token；`strict` 档起**操作码编号逐会话打乱**，写死的 VM 模拟器每次都会失效。

这是瑞数五代、`acw_sc__v2`、`a_bogus` 那一类防御的核心原理——门槛不在混淆，在**程序本身每会话都不同**。

用 `vm-guarded` profile 跑一遍，结果很干净：

```
══ vm-guarded ══
攻击实现      级    真值    实测/万条   合计/万条   主要拦截原因
signed       L1      0           ∞          ∞    sign_missing
enveloped    L4      0           ∞          ∞    sign_missing
traced       L5      0           ∞          ∞    sign_missing
browser      L4     40        0.01       0.25    —
```

**五个纯 HTTP 攻击实现全部失败，只有真浏览器过得去。** 其中 `enveloped` 靠手写一份自洽的环境 JSON 能过 L4 的 `env` 机制，但在 `vm` 面前失效——这正是"校验声明"与"要求证明"的区别。

两条设计上的讲究：

- **无状态可复现**：程序完全由 session 派生，服务端不存任何东西就能复算；同一个 session 在任何机器上拿到同一段字节码
- **每个请求都要跑一次**：VM 输入含 `ts`/`nonce`，token 不是每会话常量，跑一次不能跨请求重放

为保证第二条，程序收尾把每个输入各经一个 32 位双射折进累加器。这不是装饰——实测表明纯自由随机的主体有 **80% 以上**的概率把某个输入的影响彻底抹掉（`AND`/`OR`/`SHR`/乘偶数都销毁信息位），那样 token 就退化成常量，整个机制失效。

服务端（Python）与客户端（JS）的 32 位语义必须逐位一致，差一位就变成随机拒绝合法客户端。测试真的起一个 Node 进程执行发出的 JS 并比对。

### tlsfront：真实的 TLS 指纹

L2 要想是真的，就必须有个组件在 TCP 字节流上解析 ClientHello——TLS 指纹由客户端的 **TLS 栈**决定，握手一结束就没了，应用层中间件根本看不到。

`range/tlsfront` 是一个 TLS 终结代理。核心技巧是 `ssl.MemoryBIO`：先把第一条 TLS 记录从裸 socket 读出来（**不交给 TLS 状态机**），解析算出 JA3，再把原始字节**原样喂回** BIO 驱动握手。握手成功后转发明文 HTTP，并**强制覆盖** `X-BW-JA3`——客户端自报的一律丢弃。

实测（三种客户端，各连两次）：

```
python-urllib   e13a080178d6052cad07cde7ba6232d0
curl            cd911cdb3ae1af6c7bc940cdcad83a1a
node-https      74fc12d4399034848f23564f342e65b9
```

三者互异、各自稳定。而且**换 UA 换不掉 TLS 指纹**——这正是交叉校验能成立的根本原因：伪造方改不动握手。

最容易致命的一处是 **GREASE 剔除**（RFC 8701）：浏览器每次连接都会随机插保留值，不剔除的话同一个浏览器每次算出的 JA3 都不同，机制作废——症状还是"偶尔拦错人"，极难排查。

#### 让 L2 对你机器为真：录制指纹集

默认 profile 用的 `demo.yaml` 全是**占位符**——开箱即用、不依赖你的环境，但也因此 **L2 的测量数据不具备对外可比性**。要让它变成真的，录一份自己的：

```bash
cd range
python -m tools.record_fingerprints --out fingerprints/local.yaml
```

它会自动驱动本机上找得到的每个客户端各连一次：

```
python-urllib        e13a080178d6052cad07cde7ba6232d0
curl                 cd911cdb3ae1af6c7bc940cdcad83a1a
node-https           74fc12d4399034848f23564f342e65b9
chromium-headless    c8fc783bd9c1a321133ac74bcda58eb1
```

然后把 profile 里的 `fingerprints: builtin:demo` 改成 `builtin:local`。

本机装的 Chrome / Firefox / Safari 本体、以及 `curl_cffi` 的各个 impersonate 目标自动录不到（需要图形界面或额外装包）——用交互式的 `python -m tlsfront record` 补录，格式一样可以合并。

仓库里的 [`recorded-example.yaml`](range/fingerprints/recorded-example.yaml) 是在一台 Linux 机器上录的**真实**指纹，可以直接对比真浏览器与脚本客户端的 `ja3_string` 差多少（Chromium 的密码套件明显更少、扩展顺序也不同，这正是 L2 判定的依据）。**但别直接拿它用**——你的客户端版本一旦不同，真浏览器就会被判为"不在白名单"。每条记录都带了录制时的版本号，就是为了让这种过期可被发现。

### 图片验证码：把"这个范式已经死了"做成可以跑的

`static_image` 是服务端生成的扭曲字符图。它在大流量消费站点已基本绝迹，但在**政企与传统行业后台**（招投标、司法文书、工商、教务）仍大量存在——那正是相当一部分采集业务的实际目标。

它为什么死了，靶场不靠断言，靠一条命令：

```console
$ cd range && python -m tools.captcha_dataset --count 5000 --out /tmp/ds --difficulty paranoid
导出 5000 张（paranoid）到 /tmp/ds
  耗时 23.6s，212 张/秒
  共 128.1 MB，标签在文件名与 labels.jsonl 里
```

**结构性死穴：生成图像的程序同时知道答案。** 训练集是免费的，一万张不到一分钟，分布与线上完全一致。加难度不解决问题——攻击方的训练数据和你的生成器是同一个东西；而加难度会让**人类失败率涨得比机器快**。

三档难度对应历史上的军备竞赛，也演示了这条路走到了哪：`lenient` 一眼可读，`strict` 要看一下，`paranoid` 已经接近人类可用性的上限。三档都挡不住自训模型。

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
.venv/bin/python -m pytest                              # 180 passed
```

### 一、看成本决策表（附带工具）

`harness/` 是靶场的附属工具，不是本项目的主体：它把攻击实现跑在一个强制计量的反向代理后面，算出"突破这套防御每万条数据要花多少钱"。

```console
$ .venv/bin/botwall scan -p cdn-standard -p api-signed -n 100

══ cdn-standard [diagnostic/gate] ══
攻击实现      级    真值   请求      R     实测/万条   摊销/万条   合计/万条   主要拦截原因
naive        L0      0     15      ∞           ∞       0.02         ∞    ja3_absent
spoofed      L0    100      5   1.00×   1.25e-04       0.08      0.08    —
signed       L1    100      6   1.00×   1.29e-04       0.96      0.96    —
traced       L5    100      6   1.00×   1.80e-04       2.24      2.24    —

  → 最优：spoofed（阶梯 L0），合计 0.08 / 万条
     误判成本：错选 traced（L5）要多付 28.0 倍
```

最后一行量化了一个常见且昂贵的误判：在 L2 被拦时换个客户端库就够（成本增量≈0），误以为"要上浏览器"要多付 28 倍。`legacy-gov` 上这个倍数是 139。**这正是靶场归因能力的直接价值**——真实站点不会告诉你被哪层拦了，于是这种误判无从避免。

**实测列由 harness 强制计量，攻击实现无法影响；摊销列来自申报工时，harness 无法核实。两者永远分列，不混合。** 详见 [`harness/README.md`](harness/README.md)。

### 二、看靶场的归因输出

```bash
BW_PROFILE=hardened .venv/bin/uvicorn app.main:app --port 8900 --app-dir range
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
$ .venv/bin/botwall scan -p api-signed -a naive --mode blind -n 100
naive       L0        0      5      ∞           ∞       0.02         ∞    —
              ⚠ 收到 100 条投毒数据（HTTP 200 但内容是假的）
```

HTTP 全 200、没有任何失败信号、归因栏是空的，而真值 0 条。**只统计状态码的采集器会悄无声息地采走垃圾**，并因此高估通过率、低估单位成本。

### 内置 profile

| Profile | 组合 | 对应现实 |
|---|---|---|
| `open` | 全关 | 基线，测量纯采集成本本身 |
| `legacy-gov` | L1 宽松 + L6 `static_image` | 政企/传统行业后台 |
| `cdn-standard` | L1 + L2 | 挂了标准 CDN 防护的普通站点 |
| `api-signed` | L1 + L2 + L3 | 国内主流内容平台 Web 端 |
| `hardened` | 六层全开，评分形态 | 高价值目标 |
| `vm-guarded` | L1+L2 + L3 `salt_mode: vm` + L4 `mechanism: vm` | 瑞数 / acw_sc__v2 / a_bogus 那一类 |
| `gesture-guarded` | L1+L2+L3 + L5 `mechanism: task` | 行为风控型：成本是时间而非算力 |

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

v0.1，靶场六层可用（含随机化 VM 挑战），附带的成本 harness 也能跑出第一组数据。

**已完成**
- **靶场**：六层防御，可独立开关、分 `lenient`/`strict`/`paranoid` 三档；`gate`/`score` 两种判定形态，`diagnostic`/`blind` 两种响应模式；7 个内置 profile
- **随机化 VM 挑战**：L4 的 `vm` 机制 —— 逐会话生成的栈机字节码 + 打乱的操作码表。成本是**信息壁垒**：你不知道怎么算
- **几何任务**：L5 的 `task` 机制 —— 每请求新鲜的路点 + 减速判据 + 配速核对。成本是**物理壁垒**：你必须真的花时间走过去
- **harness**：强制计量的反向代理（攻击实现拿不到靶场真实地址，无法绕过计量）、成本模型、阶梯扫描、决策表输出
- 6 个攻击实现构成完整阶梯（L0 → L5），含一个真浏览器实现（Playwright 跑站点自己的 JS）
- **一个关于成本模型自身的发现**：几何任务让墙钟涨 1.8×，但按 CPU 计价的成本模型完全看不见（1.00×）——时间型防御对它是结构性盲区。已如实记入 `harness/README.md`
- **交叉点分析**：`browser` 与 `signed` 是两条相反的经济路径（边际成本 vs 一次性逆向工时）。`browser` 加载整页约 800 KB 资产，边际成本实测是 `signed` 的约 48 倍。模型给出"采集量大到多少才值得逆向"的量化答案，且强烈依赖代理档位——datacenter 档约 8.5 亿条/年，residential 档约 1500 万条/年（代理越贵，逆向越早回本）
- **tlsfront**：TLS 终结代理，用 MemoryBIO 在握手完成前截获 ClientHello 算 JA3，含 GREASE 剔除
- **图片验证码**：L6 的 `static_image`，确定性渲染 + 三档难度，配数据集导出工具把"训练集免费"做成可跑的论证
- **指纹集录制**：`tools.record_fingerprints` 自动驱动本机各客户端（含真 Chromium）录出真实 JA3
- 180 项测试，含端到端、跨语言（Python↔Node）VM 一致性比对、多客户端真实 TLS 指纹比对

**未完成**
- **引入真实代理延迟与失败率**。整页流量已建模（`browser` 加载约 800 KB 资产，边际成本实测约为 `signed` 的 48 倍），但页面权重是可调估计值、且未含代理延迟——这是交叉点数字的主要不确定来源
- HTTP/2 指纹（Akamai 指纹）。当前只做了 JA3，tlsfront 转发时降级为 HTTP/1.1
- 容器化 + cgroup 计量（当前用 `getrusage`，能透传捕获 chromium 的 CPU，但隔离不彻底，且只支持 Python 攻击实现）
- LLM token 计量，用于接入 VLM 类攻击实现
- `sign.js` 的混淆构建。当前可读，因此 `derived` 档的逆向难度被显著低估

**已知限制**
- 默认 profile 用占位指纹集，所以**开箱状态下 L2 的数据不可对外引用**。录一份自己的即可转为真实（见上文）
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
