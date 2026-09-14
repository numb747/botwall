/**
 * botwall 靶场的参考客户端。
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

/** vm 档：derived 的结果再与 VM 执行结果绑定。对应 signing.vm_salt。 */
async function vmSalt(seed, vmToken) {
  const base = await deriveSalt(seed);
  return (await sha256Hex(base + vmToken)).slice(0, 16);
}

// --- VM 挑战（L4 的 vm 机制）---

/** 32 位 FNV-1a。VM 的第三个输入。对应 vm.fnv1a。 */
function fnv1a(text) {
  let h = 0x811c9dc5;
  const bytes = new TextEncoder().encode(text);
  for (const byte of bytes) {
    h = Math.imul(h ^ byte, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

let vmCache = null;

/**
 * 取本会话的 VM 挑战并编译。
 *
 * 服务端下发的是一段解释随机字节码的 JS 函数体——注意**程序每会话都不同**，
 * 所以这里不能缓存跨会话的结果，也不可能预先把它逆向掉。
 */
async function loadVm() {
  if (vmCache) return vmCache;
  const res = await fetch("/api/vm-challenge", { credentials: "same-origin" });
  if (!res.ok) return null;
  const { vm, seed32 } = await res.json();
  // eslint-disable-next-line no-new-func -- 执行服务端下发的挑战正是本机制的要点
  vmCache = { run: new Function("I", vm), seed32 };
  return vmCache;
}

/** 用 (seed32, ts, nonce) 跑一次 VM，得到 8 位十六进制 token。 */
async function vmToken(ts, nonce) {
  const loaded = await loadVm();
  if (!loaded) return "";
  // ts 是毫秒数，超过 32 位，取低 32 位——服务端 make_inputs 同样处理
  const tsLow = Number(BigInt(ts) & 0xffffffffn);
  const value = loaded.run([loaded.seed32 >>> 0, tsLow >>> 0, fnv1a(nonce)]);
  return (value >>> 0).toString(16).padStart(8, "0");
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
    ctx.fillText("botwall \u{1F512}", 2, 2);
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
    if (now - last < 6) return;
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

// --- 几何任务（L5 的 task 机制）---

/** xorshift32。对应 gesture.xorshift32。用它而不是 sha256，是因为要同步算。 */
function xorshift32(state) {
  state = state >>> 0;
  state = (state ^ (state << 13)) >>> 0;
  state = (state ^ (state >>> 17)) >>> 0;
  state = (state ^ (state << 5)) >>> 0;
  return state >>> 0;
}

/**
 * 由 (session, ts, nonce) 派生本次请求的路点。对应 gesture.derive_task。
 *
 * 注意路点**不保密**——客户端自己就能算，不用问服务端。难的不是知道去哪，
 * 是必须真的花时间走过去。
 */
export function deriveWaypoints(session, ts, nonce, count = 4, width = 640, height = 360, tolerance = 18) {
  let state = fnv1a(`${session}|${ts}|${nonce}`) >>> 0;
  if (state === 0) state = 1; // xorshift 的 0 是吸收态
  const margin = tolerance * 2;
  const points = [];
  for (let i = 0; i < count; i++) {
    state = xorshift32(state);
    const x = margin + (state % Math.max(1, width - 2 * margin));
    state = xorshift32(state);
    const y = margin + (state % Math.max(1, height - 2 * margin));
    points.push([x, y]);
  }
  return points;
}

/**
 * 驱动真实指针依次走过路点。
 *
 * 每一段用最小抖动剖面（起步慢、中段快、接近目标减速）。减速不是装饰：
 * 服务端会检查路点附近的局部速度低于全程均速，匀速插值过不了。
 *
 * 这个函数必须由**真实的指针事件**来实现——在浏览器里就是等待 mousemove
 * 真的发生。它花掉的墙钟时间是这一层无法压缩的成本。
 */
export async function performGesture(waypoints, stepMs = 20) {
  const surface = document.getElementById("surface") || document.body;
  let [cx, cy] = [waypoints[0][0], waypoints[0][1]];
  for (const [tx, ty] of waypoints) {
    const steps = 12 + Math.floor(Math.random() * 8);
    const [sx, sy] = [cx, cy];
    for (let i = 1; i <= steps; i++) {
      const p = i / steps;
      // 最小抖动：位移剖面 3p²-2p³，端点速度为 0 —— 天然满足"接近时减速"
      const ease = p * p * (3 - 2 * p);
      const jitter = (Math.random() - 0.5) * 2;
      const x = Math.round(sx + (tx - sx) * ease + jitter);
      const y = Math.round(sy + (ty - sy) * ease + jitter);
      surface.dispatchEvent(
        new MouseEvent("mousemove", { clientX: x, clientY: y, bubbles: true })
      );
      await new Promise((r) => setTimeout(r, stepMs));
    }
    [cx, cy] = [tx, ty];
  }
}

// --- 签名请求 ---

/** 读服务端种下的会话 cookie。几何任务的路点按它派生。 */
function sessionId() {
  const m = document.cookie.match(/(?:^|;\s*)bw_session=([^;]+)/);
  return m ? m[1] : "";
}

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
    headers["X-BW-Env"] = envSnapshot;
  }

  // VM token 既可能被 L3 的 vm 档用来算 salt，也可能被 L4 的 vm 机制单独校验，
  // 所以只要挑战可取就算上：拿不到（未启用）时 loadVm 返回 null，这里得空串。
  const token = await vmToken(ts, nonce);
  if (token) headers["X-BW-VM"] = token;

  // L5 的 task 机制：路点由 (session, ts, nonce) 派生，所以必须在 ts/nonce
  // 定下来之后才能走。这段手势会真的花掉几百毫秒——那正是这一层的成本所在。
  const boot = await bootstrap();
  if (boot.gesture && boot.gesture.enabled) {
    const session = sessionId();
    const g = boot.gesture;
    const waypoints = deriveWaypoints(
      session, ts, nonce, g.waypoints, g.canvas_width, g.canvas_height, g.tolerance
    );
    trace.length = 0; // 只保留本次手势，避免旧点把路点顺序搅乱
    await performGesture(waypoints);
  }

  let salt;
  if (saltMode === "static") {
    // static 档的 salt 明文写死在这里 —— 读一遍这个文件即可复现。
    salt = "bw-demo-salt";
  } else if (saltMode === "derived") {
    salt = await deriveSalt(seed);
  } else if (saltMode === "runtime") {
    salt = await runtimeSalt(seed, envSnapshot);
  } else if (saltMode === "vm") {
    salt = await vmSalt(seed, token);
  } else {
    salt = null; // L3 未启用
  }

  if (salt !== null) {
    const payload = canonicalPayload("GET", path, canonicalQuery(query), ts, nonce);
    headers["X-BW-Ts"] = ts;
    headers["X-BW-Nonce"] = nonce;
    headers["X-BW-Sign"] = (await sha256Hex(salt + payload)).slice(0, 32);
  }

  if (trace.length > 0) headers["X-BW-Trace"] = traceHeader();

  const qs = query.toString();
  return fetch(qs ? `${path}?${qs}` : path, { headers, credentials: "same-origin" });
}
