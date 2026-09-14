/**
 * CostLadder 靶场的参考客户端。
 *
 * 这份实现是"正确答案"——它展示一个合法客户端该怎么签名、怎么上报环境与轨迹。
 * 攻击侧的任务是在**不读这个文件**的前提下，从抓包结果复现出同样的行为。
 *
 * 注意 `derive` 在这里是可读的。真实站点会把这段逻辑混淆或放进 JS 虚拟机，
 * 那正是把攻击方从成本阶梯 L1 顶到 L3 的手段。混淆构建是本项目的后续工作，
 * 当前版本保持可读，以便先跑通完整链路。
 *
 * 服务端的等价实现在 range/app/signing.py —— 改这里就必须同步改那里。
 */

const enc = new TextEncoder();

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** derived 档的 salt 变换。对应 signing.derive_salt。 */
async function deriveSalt(seed) {
  let checksum = 0;
  for (const ch of seed) checksum += ch.codePointAt(0);
  checksum %= 997;
  const reversed = [...seed].reverse().join("");
  return (await sha256Hex(`${reversed}${checksum}`)).slice(0, 16);
}

/** runtime 档：derived 的结果再与环境快照绑定。对应 signing.runtime_salt。 */
async function runtimeSalt(seed, envSnapshot) {
  const base = await deriveSalt(seed);
  return (await sha256Hex(base + envSnapshot)).slice(0, 16);
}

/**
 * 查询参数按 key 排序后以 & 连接。
 * 注意：JS 默认排序按 UTF-16 码元，Python 的 sorted 按码点。ASCII 键名下两者
 * 一致；若引入非 ASCII 键名，两端必须同时改成同一套比较规则。
 */
function canonicalQuery(params) {
  const keys = [...params.keys()].sort();
  return keys.map((k) => `${k}=${params.get(k)}`).join("&");
}

function canonicalPayload(method, path, query, ts, nonce) {
  return [method.toUpperCase(), path, query, ts, nonce].join("\n");
}

// --- 环境快照（L4 用） ---

function webglInfo() {
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    if (!gl) return { vendor: "", renderer: "" };
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    if (!ext) return { vendor: gl.getParameter(gl.VENDOR), renderer: gl.getParameter(gl.RENDERER) };
    return {
      vendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),
      renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL),
    };
  } catch {
    return { vendor: "", renderer: "" };
  }
}

async function canvasHash() {
  try {
    const c = document.createElement("canvas");
    c.width = 220;
    c.height = 40;
    const ctx = c.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.fillStyle = "#f60";
    ctx.fillRect(0, 0, 100, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("CostLadder \u{1F512}", 2, 2);
    return (await sha256Hex(c.toDataURL())).slice(0, 32);
  } catch {
    return "";
  }
}

/** 采集环境快照并编码为 base64(JSON)。 */
export async function collectEnv() {
  const t0 = performance.now();
  const gl = webglInfo();
  const env = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: [...navigator.languages],
    hardwareConcurrency: navigator.hardwareConcurrency,
    webdriver: navigator.webdriver === true,
    webglVendor: gl.vendor,
    webglRenderer: gl.renderer,
    canvasHash: await canvasHash(),
    windowKeys: Object.keys(window).filter((k) => k.startsWith("cdc_") || k.startsWith("__")),
    collectMs: 0,
  };
  env.collectMs = Math.round((performance.now() - t0) * 100) / 100;
  return btoa(JSON.stringify(env));
}

// --- 交互轨迹（L5 用） ---

const trace = [];
const TRACE_MAX = 200;

export function startTracing(target = document) {
  const push = (type) => (ev) => {
    if (trace.length >= TRACE_MAX) trace.shift();
    trace.push({
      t: Math.round(performance.now() * 100) / 100,
      type,
      x: Math.round(ev.clientX ?? 0),
      y: Math.round(ev.clientY ?? 0),
    });
  };
  // mousemove 采样降频，否则 200 个点只能覆盖很短的时间窗
  let last = 0;
  target.addEventListener("mousemove", (ev) => {
    const now = performance.now();
    if (now - last < 16) return;
    last = now;
    push("mousemove")(ev);
  });
  for (const type of ["mousedown", "mouseup", "click"]) {
    target.addEventListener(type, push(type));
  }
}

export function traceHeader() {
  return btoa(JSON.stringify(trace));
}

// --- 签名请求 ---

let bootstrapCache = null;

async function bootstrap() {
  if (bootstrapCache) return bootstrapCache;
  const res = await fetch("/api/bootstrap", { credentials: "same-origin" });
  bootstrapCache = await res.json();
  return bootstrapCache;
}

/**
 * 发起一次带签名的请求。
 *
 * @param {string} path  例如 "/api/items"
 * @param {object} params 查询参数
 */
export async function signedFetch(path, params = {}) {
  const { seed, salt_mode: saltMode } = await bootstrap();
  const query = new URLSearchParams(params);
  const ts = String(Date.now());
  const nonce = crypto.randomUUID().replace(/-/g, "");

  const headers = {};
  let envSnapshot = "";
  if (saltMode === "runtime") {
    envSnapshot = await collectEnv();
    headers["X-CL-Env"] = envSnapshot;
  }

  let salt;
  if (saltMode === "static") {
    // static 档的 salt 明文写死在这里 —— 读一遍这个文件即可复现。
    salt = "cl-demo-salt";
  } else if (saltMode === "derived") {
    salt = await deriveSalt(seed);
  } else if (saltMode === "runtime") {
    salt = await runtimeSalt(seed, envSnapshot);
  } else {
    salt = null; // L3 未启用
  }

  if (salt !== null) {
    const payload = canonicalPayload("GET", path, canonicalQuery(query), ts, nonce);
    headers["X-CL-Ts"] = ts;
    headers["X-CL-Nonce"] = nonce;
    headers["X-CL-Sign"] = (await sha256Hex(salt + payload)).slice(0, 32);
  }

  if (trace.length > 0) headers["X-CL-Trace"] = traceHeader();

  const qs = query.toString();
  return fetch(qs ? `${path}?${qs}` : path, { headers, credentials: "same-origin" });
}
