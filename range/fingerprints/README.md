# 指纹集

L2 传输层的判定依赖这里的 JA3 名单。

## ⚠️ 内置的 demo.yaml 全是占位符

`demo.yaml` 里的值不是真实浏览器或 HTTP 客户端的 JA3。它们够跑通 L2 的判定逻辑和单元测试，但**用它们测出来的数据不具备对外可比性**。

## 为什么不预置真值

JA3 随浏览器版本变化。写死在仓库里的真实指纹几个月就过期，而过期的指纹会让 L2 的测量结果系统性偏高——真浏览器也会被判为"不在白名单"。让使用者录制自己的，是唯一能保证数据有效的做法。

## 怎么录制自己的

需要 `tlsfront` 组件（解析 ClientHello 计算 JA3 的前置代理）。**该组件尚未实现**，见根目录 README 的「当前状态」。

它就位后的流程会是：

1. 启动 `tlsfront`，它会把每个连接的 JA3 记录下来
2. 用你要测的每个客户端（真 Chrome、真 Firefox、`requests`、`curl_cffi` 的各个 impersonate 目标……）各访问一次
3. 导出为 `fingerprints/local.yaml`
4. 在 profile 里把 `fingerprints: builtin:demo` 改成 `builtin:local`

录制时必须记录浏览器的**完整版本号**，并把它写进文件头。没有版本号的指纹集在几个月后无法判断是否还有效。

## 格式

```yaml
# ja3 -> 客户端名。命中即判定为脚本库，不看强度档。
script_clients:
  <ja3>: "python-requests"

# ja3 -> 浏览器族。strict 档要求命中本表；
# paranoid 档还要求与 UA 声明的浏览器族一致。
browsers:
  <ja3>: "chrome"
```

浏览器族的取值必须来自 `app/layers/l2_transport.py` 的 `_UA_FAMILY_PATTERNS`：
`chrome` / `firefox` / `safari` / `edge` / `opera`。
