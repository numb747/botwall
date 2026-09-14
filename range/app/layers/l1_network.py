"""L1 网络层 —— 只看来源 IP 本身，以及该 IP 的请求节奏。

被本层拦住意味着代理档位不够，对应成本阶梯上从数据中心 IP 升级到住宅/移动 IP。
这是成本倍数最直观的一跳：住宅代理按流量计费，通常比数据中心 IP 贵一到两个数量级。
"""

from __future__ import annotations

import ipaddress
from typing import ClassVar

from ..core import Probe, RangeState, Strength, Verdict
from .base import Layer

#: 数据中心网段样例表。
#: 真实部署应换成完整的 ASN 数据库（如 MaxMind ASN 或 IP2Location）。
#: 这里只放少量确定属于云厂商的公开网段，够跑通判定逻辑，不追求覆盖率。
#: profile 可以通过 options.datacenter_cidrs 整体替换本表。
DEFAULT_DATACENTER_CIDRS: tuple[str, ...] = (
    "3.0.0.0/8",  # AWS
    "13.64.0.0/11",  # Azure
    "34.64.0.0/10",  # GCP
    "35.184.0.0/13",  # GCP
    "104.196.0.0/14",  # GCP
    "159.89.0.0/16",  # DigitalOcean
    "167.71.0.0/16",  # DigitalOcean
    "45.32.0.0/16",  # Vultr
    "172.104.0.0/15",  # Linode
)

#: 本地与私有网段。开发时默认放行，否则靶场自己都跑不起来。
LOCAL_NETS = ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def _in_any(ip: str, cidrs: tuple[str, ...] | list[str]) -> str | None:
    """返回命中的网段，未命中返回 None。IP 不可解析时视为未命中。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return cidr
    return None


class NetworkLayer(Layer):
    id: ClassVar[str] = "l1_network"
    name: ClassVar[str] = "网络层"
    ladder_rung: ClassVar[int] = 2  # 被拦 -> 需要住宅/移动 IP，即阶梯 L2

    def inspect(self, probe: Probe, state: RangeState) -> Verdict:
        ip = probe.client_ip
        window = float(self.opt("window_seconds", 60.0))
        max_requests = int(self.opt("max_requests", 60))

        count = state.record_request(ip, probe.received_at, window)
        if count > max_requests:
            return self._fail(
                "rate_exceeded",
                score=float(self.opt("rate_score", 0.6)),
                window_seconds=window,
                observed=count,
                limit=max_requests,
            )

        allow_local = bool(self.opt("allow_local", True))
        is_local = _in_any(ip, LOCAL_NETS) is not None

        if self.strength.at_least(Strength.STRICT) and self.opt("reject_datacenter", True):
            if not (allow_local and is_local):
                cidrs = self.opt("datacenter_cidrs", DEFAULT_DATACENTER_CIDRS)
                hit = _in_any(ip, cidrs)
                if hit:
                    return self._fail(
                        "datacenter_asn",
                        score=float(self.opt("datacenter_score", 1.0)),
                        ip=ip,
                        matched_cidr=hit,
                    )

        if self.strength is Strength.PARANOID:
            session = probe.cookies.get("cl_session") or probe.header("x-cl-session")
            if session:
                state.ip_sessions[ip].add(session)
            limit = int(self.opt("max_sessions_per_ip", 2))
            observed = len(state.ip_sessions[ip])
            if observed > limit:
                return self._fail(
                    "session_concurrency",
                    score=float(self.opt("concurrency_score", 0.5)),
                    observed=observed,
                    limit=limit,
                )

        return self._ok(window_count=count, is_local=is_local)
