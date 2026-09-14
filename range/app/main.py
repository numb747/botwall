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

from . import __version__, data
from .config import Profile, list_profiles, load_profile
from .core import Probe, RangeState
from .gate import Gate, GateResult
from .layers import ProtocolLayer, build_layers

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


def _ensure_session(request: Request, response: Response) -> str:
    session = request.cookies.get(SESSION_COOKIE)
    if not session:
        session = secrets.token_hex(8)
        response.set_cookie(SESSION_COOKIE, session, httponly=False, samesite="lax")
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
    response = JSONResponse({})
    session = _ensure_session(request, response)
    if gate.captcha is None:
        return JSONResponse({"error": "L6 未启用"}, status_code=404)
    return JSONResponse(gate.captcha.issue_challenge(session, state), headers=response.headers)


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
