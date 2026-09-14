"""自签证书 —— 只用于本地靶场。

证书不进仓库：每台机器自己生成一份。仓库里带私钥是绝对不该做的事，哪怕
它只是个 localhost 的自签证书——那会教坏照抄的人。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parent / "certs"


def ensure_cert(directory: Path | None = None, common_name: str = "localhost") -> tuple[str, str]:
    """返回 (certfile, keyfile)，不存在就用 openssl 现生成一份。"""
    target = directory or DEFAULT_DIR
    target.mkdir(parents=True, exist_ok=True)
    certfile, keyfile = target / "cert.pem", target / "key.pem"
    if certfile.exists() and keyfile.exists():
        return str(certfile), str(keyfile)

    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(keyfile), "-out", str(certfile),
            "-days", "365", "-nodes", "-subj", f"/CN={common_name}",
            "-addext", f"subjectAltName=DNS:{common_name},IP:127.0.0.1",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"生成自签证书失败（需要 openssl）:\n{result.stderr}")
    keyfile.chmod(0o600)
    return str(certfile), str(keyfile)
