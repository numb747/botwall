"""靶场 HTTP 服务。

启动：
    cd range && uvicorn app.main:app --reload --port 8900
选择 profile：
    CL_PROFILE=api-signed uvicorn app.main:app --port 8900

端点：
    GET  /                受保护的数据接口在哪、当前 profile 是什么
    GET  /api/items       **受保护的数据接口**，六层判定在这里生效
    GET  /api/bootstrap   下发签名所需的 seed（模拟真实站点的页面内联数据）
    GET  /api/challenge   主动领取一道 L6 挑战
    GET  /meta/profile    当前 profile 的层配置（diagnostic 模式下可见）
    GET  /static/sign.js  参考客户端的签名实现
"""

from __future__ import annotations

import os
import secrets
from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, assets, data, vm
from .config import Profile, list_profiles, load_profile
from .core import Probe, RangeState
from .gate import Gate, GateResult
from .layers import ProtocolLayer, RuntimeLayer, build_layers

RANGE_ROOT = Path(__file__).resolve().parent.parent
SESSION_COOKIE = "cl_session"


def _build(profile: Profile) -> tuple[Gate, list]:
    layers = build_layers(profile.layers)
    gate = Gate(
        layers,
        form=profile.form,
        mode=profile.mode,
        score_threshold=profile.score_threshold,
        captcha_trigger_score=profile.captcha_trigger_score,
    )
    return gate, layers


def _load() -> Profile:
    """加载 profile，允许用环境变量覆盖 mode / form。

    覆盖存在是因为成本模型的核心实验之一就是拿**同一个 profile** 跑
    diagnostic 和 blind 两遍，差值即排障工时 T_diag。为此专门复制一份
    profile 文件既繁琐又容易漂移。form 同理：gate 与 score 形态下同一套
    攻击实现的成本差，本身就是一个要测的量。
    """
    profile = load_profile(os.environ.get("CL_PROFILE", "open"))
    mode = os.environ.get("CL_MODE")
    form = os.environ.get("CL_FORM")
    if mode or form:
        profile = replace(profile, mode=mode or profile.mode, form=form or profile.form)
    return profile


profile = _load()
gate, active_layers = _build(profile)
state = RangeState()

app = FastAPI(
    title="CostLadder Range",
    version=__version__,
    description="可逐层开关的反自动化防御靶场。只用于本地测量，不针对任何第三方服务。",
)
app.mount("/static", StaticFiles(directory=RANGE_ROOT / "app" / "static"), name="static")


async def make_probe(request: Request) -> Probe:
    import time

    body = await request.body()
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "0.0.0.0"
    return Probe(
        method=request.method,
        path=request.url.path,
        query=dict(request.query_params),
        headers={k.lower(): v for k, v in request.headers.items()},
        cookies=dict(request.cookies),
        body=body,
        client_ip=client_ip,
        received_at=time.time(),
    )


def _session_id(request: Request) -> str:
    """取会话 id；没有就现造一个。

    与 _ensure_session 分开，是因为有些端点（如 VM 挑战）需要在**构造响应体
    之前**就知道会话 id。以前只有 _ensure_session，调用方被迫先造一个空响应
    去骗出 cookie、再把它的 headers 整套复制给真响应——而那套 headers 里带着
    空响应的 Content-Length，于是真响应的长度对不上，ASGI 层直接报
    "Response content longer than Content-Length"。
    """
    return request.cookies.get(SESSION_COOKIE) or secrets.token_hex(8)


def _attach_session(request: Request, response: Response, session: str) -> None:
    """只在会话是新造的时候种 cookie。不碰响应的其他头。"""
    if request.cookies.get(SESSION_COOKIE) != session:
        response.set_cookie(SESSION_COOKIE, session, httponly=False, samesite="lax")


def _ensure_session(request: Request, response: Response) -> str:
    session = _session_id(request)
    _attach_session(request, response, session)
    return session


@app.get("/")
async def index() -> dict[str, Any]:
    return {
        "range": "CostLadder",
        "version": __version__,
        "profile": profile.stamp,
        "description": profile.description,
        "mode": profile.mode,
        "form": profile.form,
        "enabled_layers": profile.enabled_layers(),
        "protected_endpoint": "/api/items?offset=0&limit=20",
        "available_profiles": list_profiles(),
        "note": "本靶场仅用于本地成本测量，不针对任何第三方服务。见 docs/04-scope.md。",
    }


@app.get("/api/vm-challenge")
async def vm_challenge(request: Request) -> Response:
    """下发本会话的 VM 挑战：一段解释随机字节码的 JS 函数体。

    用法（客户端）：
        const {vm} = await (await fetch("/api/vm-challenge")).json();
        const token = new Function("I", vm)([seed32, tsLow, fnv1a(nonce)]);

    程序由会话确定性派生，服务端不存状态；每次取到的都一样，换个会话就全变。
    真正的门槛不是混淆，是**程序本身每会话都不同**——写死的 VM 模拟器会失效。
    """
    layer = next((l for l in active_layers if isinstance(l, RuntimeLayer)), None)
    if layer is None or layer.mechanism == "env":
        return JSONResponse({"error": "本 profile 未启用 VM 挑战"}, status_code=404)

    session = _session_id(request)
    challenge = layer.challenge_for(session)
    response = JSONResponse(
        {
            "vm": vm.emit_js(challenge),
            "seed32": vm.seed32_of(challenge.seed),
            "program_length": challenge.length,
        }
    )
    _attach_session(request, response, session)
    return response


@app.get("/assets/{name}")
async def asset(name: str) -> Response:
    """页面资产（JS/CSS/图片/字体）。

    只有真浏览器加载落地页时才会拉这些——纯 HTTP 攻击实现直接打 /api/items，
    不碰这里。二者的字节差就是"能不能不用浏览器"在成本上的物理基础，
    由计量代理如实记账。内容确定性生成，不落盘。见 app/assets.py。
    """
    if name not in assets.asset_names():
        return JSONResponse({"error": "unknown asset"}, status_code=404)
    return Response(
        content=assets.asset_bytes(name),
        media_type=assets.content_type(name),
        headers={"Cache-Control": "no-store"},  # 每次都过线，模拟冷缓存采集
    )


@app.get("/meta/profile")
async def meta_profile() -> dict[str, Any]:
    if profile.mode == "blind":
        # blind 模式下连配置都不暴露——否则排障工时就没法测了
        return {"profile": profile.stamp}
    return {
        "profile": profile.stamp,
        "form": profile.form,
        "mode": profile.mode,
        "score_threshold": profile.score_threshold,
        "captcha_trigger_score": profile.captcha_trigger_score,
        "layers": profile.layers,
    }


@app.get("/api/bootstrap")
async def bootstrap(request: Request) -> Response:
    """下发签名所需的 seed。

    真实站点通常把它内联在页面 HTML 或首屏 JS 里；靶场用一个独立端点代替，
    目的一样：seed 是公开可得的，难点不在拿到 seed，在于复现 seed -> salt
    的变换以及签名的序列化规则。
    """
    layer = next((l for l in active_layers if isinstance(l, ProtocolLayer)), None)
    response = JSONResponse(
        {
            "seed": layer.seed if layer else None,
            "salt_mode": layer.salt_mode if layer else None,
            "ts_window_seconds": layer.ts_window if layer else None,
        }
    )
    _ensure_session(request, response)
    return response


@app.get("/api/challenge")
async def challenge(request: Request) -> Response:
    """主动领取一道 L6 挑战。

    注意这个端点的存在本身不代表验证码是常规关卡——它只是让客户端在被
    captcha_required 拦下后有地方拿题。默认 profile 里 L6 是关闭的。
    """
    if gate.captcha is None:
        return JSONResponse({"error": "L6 未启用"}, status_code=404)
    session = _session_id(request)
    response = JSONResponse(gate.captcha.issue_challenge(session, state))
    _attach_session(request, response, session)
    return response


@app.get("/api/items")
async def items(request: Request) -> Response:
    probe = await make_probe(request)
    result: GateResult = gate.evaluate(probe, state)

    offset = int(probe.query.get("offset", 0) or 0)
    limit = int(probe.query.get("limit", 20) or 20)

    if result.allowed:
        response = JSONResponse(data.page(offset, limit))
        _ensure_session(request, response)
        return response

    if profile.mode == "blind":
        # 不告诉攻击者失败了：返回结构合法但内容错误的数据。
        # 这是最有效的反制之一，也是本靶场测量排障工时 T_diag 的手段。
        response = JSONResponse(data.page(offset, limit, poisoned=True))
        _ensure_session(request, response)
        return response

    body = result.diagnostic_body()
    if result.challenge is not None:
        body["challenge"] = result.challenge
    response = JSONResponse(body, status_code=403)
    _ensure_session(request, response)
    return response


@app.post("/meta/reset")
async def reset() -> dict[str, str]:
    """清空跨请求状态。测试之间的隔离用。"""
    state.reset()
    return {"status": "reset"}
